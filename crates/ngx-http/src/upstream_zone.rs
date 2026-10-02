//! ngx_http_upstream_zone_module: "zone name [size]". The peers of the
//! upstreams in a zone are copied to its shared memory, shared by the
//! workers; servers with "resolve" are resolved there at run time by
//! worker 0, and after a reload the new peers start with the addresses
//! resolved before (preresolve).

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::inet::SockAddr;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::resolver::{ResolverCtx, Resolved, Resolver, NGX_RESOLVE_NXDOMAIN};
use ngx_core::shm::ShmZone;
use ngx_core::shmem::slab::{PoolHeader, SlabPool};
use ngx_core::shmem::ShmMem;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug, ngx_log_error};

use crate::upstream::*;
use crate::upstream_round_robin::*;
use crate::{http_module_def, HttpModuleDef, NGX_CONF_TAKE12, NGX_HTTP_UPS_CONF};

/// ngx_http_upstream_zone
fn zone_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = current_upstream(cf).ok_or_else(|| msg("\"zone\" directive is not allowed here"))?;
    let umcf = main_conf(cf);

    let value = cf.args.clone();

    if value[1].is_empty() {
        return Err(cf.emerg(format_args!("invalid zone name \"{}\"", B(&value[1]))));
    }

    let size = if value.len() == 3 {
        let size = match ngx_core::parse::parse_size(&value[2]) {
            Some(s) => s,
            None => return Err(cf.emerg(format_args!("invalid zone size \"{}\"", B(&value[2])))),
        };

        if size < 8 * ngx_core::os::pagesize() {
            return Err(cf.emerg(format_args!("zone \"{}\" is too small", B(&value[1]))));
        }

        size
    } else {
        0
    };

    let shm_zone = ngx_core::cycle::shared_memory_add(cf, &value[1], size, "ngx_http_upstream_module")?;


    *shm_zone.init.borrow_mut() = Some(Rc::new(init_zone));
    *shm_zone.data.borrow_mut() = Some(umcf);

    shm_zone.noreuse.set(true);

    *uscf.shm_zone.borrow_mut() = Some(shm_zone);

    Ok(())
}

fn zone_umcf(data: &Option<Rc<dyn Any>>) -> Option<Rc<RefCell<UpstreamMainConf>>> {
    data.clone().and_then(|d| d.downcast::<RefCell<UpstreamMainConf>>().ok())
}

/// ngx_http_upstream_init_zone: the peers of the zone's upstreams copied
/// to it; data is the upstreams of the previous configuration.
fn init_zone(shm_zone: &Rc<ShmZone>, data: Option<Rc<dyn Any>>) -> Result<(), ()> {
    let zm = PeerMem::zone(shm_zone.mem());
    let mem = &*zm.mem;
    let shpool = SlabPool::of(mem);

    let umcf = zone_umcf(&shm_zone.data.borrow()).ok_or(())?;
    let upstreams = umcf.borrow().upstreams.borrow().clone();

    let in_zone = |uscf: &Rc<UpstreamSrvConf>| uscf.shm_zone.borrow().as_ref().is_some_and(|z| Rc::ptr_eq(z, shm_zone));

    if shm_zone.shm.exists.get() {
        let mut peers = shpool.data();

        for uscf in upstreams.iter().filter(|u| in_zone(u)) {
            uscf.peers.set(Peers { mem: zm.clone(), off: peers });
            peers = RrPeers::at(mem, peers).get(RrPeers::zone_next);
        }

        return Ok(());
    }

    let ctx = format!(" in upstream zone \"{}\"", B(shm_zone.name()));
    shpool.set_log_ctx(ctx.as_bytes())?;

    // copy peers to shared memory

    // &shpool->data: the pool is at the start of the zone
    let mut peersp = PoolHeader::data.off;

    let oumcf = zone_umcf(&data);

    for uscf in upstreams.iter().filter(|u| in_zone(u)) {
        let mut ouscf: Option<Rc<UpstreamSrvConf>> = None;

        if let Some(oumcf) = oumcf.as_ref() {
            let oupstreams = oumcf.borrow().upstreams.borrow().clone();

            for o in oupstreams.iter() {
                let same_zone = o.shm_zone.borrow().as_ref().is_some_and(|z| z.name() == shm_zone.name());

                if !same_zone {
                    continue;
                }

                if o.host == uscf.host {
                    ouscf = Some(o.clone());
                    break;
                }
            }
        }

        let peers = copy_peers(&zm, uscf, ouscf.as_ref());
        if peers == 0 {
            return Err(());
        }

        mem.set(peersp, peers);
        peersp = peers + RrPeers::zone_next.off;
    }

    Ok(())
}

/// ngx_http_upstream_zone_copy_peers: the peers of the upstream (in a
/// memory of the process) copied to the zone, 0 on failure
fn copy_peers(zm: &Rc<PeerMem>, uscf: &Rc<UpstreamSrvConf>, ouscf: Option<&Rc<UpstreamSrvConf>>) -> usize {
    let mem = &*zm.mem;
    let pool = SlabPool::of(mem);

    let src = match uscf.peers.get() {
        Some(p) => p,
        None => return 0,
    };
    let smem = &*src.mem.mem;

    let opeers = ouscf.and_then(|o| o.peers.get());

    let config = pool.calloc(std::mem::size_of::<usize>());
    if config == 0 {
        return 0;
    }

    let peers = pool.alloc(RrPeers::SIZE);
    if peers == 0 {
        return 0;
    }

    // ngx_memcpy(): the links of the copy are those of the process memory
    // until the peers they link are copied in turn
    mem.write(peers, &smem.bytes(src.off, RrPeers::SIZE));

    let ps = RrPeers::at(mem, peers);

    let sname = NgxStr::at(smem, ps.get(RrPeers::name));

    let name = pool.alloc(NgxStr::SIZE);
    if name == 0 {
        return 0;
    }

    let name_data = pool.alloc(sname.get(NgxStr::len));
    if name_data == 0 {
        return 0;
    }

    mem.write(name_data, &sname.bytes());
    NgxStr::at(mem, name).set(NgxStr::data, name_data);
    NgxStr::at(mem, name).set(NgxStr::len, sname.get(NgxStr::len));

    ps.set(RrPeers::name, name);

    ps.set(RrPeers::shpool, 1);
    ps.set(RrPeers::config, config);

    if copy_list(mem, smem, peers, peers + RrPeers::peer.off).is_err() {
        return 0;
    }

    if copy_list(mem, smem, peers, peers + RrPeers::resolve.off).is_err() {
        return 0;
    }

    if let Some(o) = opeers.as_ref() {
        let omem = &*o.mem.mem;
        let oresolve = RrPeers::at(omem, o.off).get(RrPeers::resolve);

        if preresolve(mem, ps.get(RrPeers::resolve), peers, omem, oresolve, o.off).is_err() {
            return 0;
        }
    }

    let snext = ps.get(RrPeers::next);

    if snext != 0 {
        let backup = pool.alloc(RrPeers::SIZE);
        if backup == 0 {
            return 0;
        }

        mem.write(backup, &smem.bytes(snext, RrPeers::SIZE));

        let bs = RrPeers::at(mem, backup);

        bs.set(RrPeers::name, name);

        bs.set(RrPeers::shpool, 1);
        bs.set(RrPeers::config, config);

        if copy_list(mem, smem, backup, backup + RrPeers::peer.off).is_err() {
            return 0;
        }

        if copy_list(mem, smem, backup, backup + RrPeers::resolve.off).is_err() {
            return 0;
        }

        ps.set(RrPeers::next, backup);

        if let Some(o) = opeers.as_ref() {
            let omem = &*o.mem.mem;
            let os = RrPeers::at(omem, o.off);
            let onext = os.get(RrPeers::next);

            if onext != 0 {
                if preresolve(mem, ps.get(RrPeers::resolve), backup, omem, os.get(RrPeers::resolve), onext).is_err() {
                    return 0;
                }

                let onext_resolve = RrPeers::at(omem, onext).get(RrPeers::resolve);

                if preresolve(mem, bs.get(RrPeers::resolve), backup, omem, onext_resolve, onext).is_err() {
                    return 0;
                }
            }
        }
    }

    // done:

    uscf.peers.set(Peers { mem: zm.clone(), off: peers });

    set_single(uscf);

    peers
}

/// The peers of a list copied, each counted in the zone's config:
/// `peerp` is the link to the first one, an offset in the process memory
/// `smem` as every next link of the peers copied.
fn copy_list(mem: &ShmMem, smem: &ShmMem, peers: usize, mut peerp: usize) -> Result<(), ()> {
    let config = RrPeers::at(mem, peers).get(RrPeers::config);

    loop {
        let src = mem.get(peerp);

        if src == 0 {
            break;
        }

        // pool is unlocked
        let peer = copy_peer(mem, peers, Some((smem, src)));
        if peer == 0 {
            return Err(());
        }

        mem.set(peerp, peer);
        config_inc(mem, config);

        peerp = peer + RrPeer::next.off;
    }

    Ok(())
}

/// The part of ngx_http_upstream_zone_copy_peer that frees the peer it
/// failed to make.
fn copy_peer_failed(pool: &SlabPool<'_>, d: RrPeer<'_>) -> usize {
    let host = d.get(RrPeer::host);

    if host != 0 {
        let name = UpstreamHost::at(d.mem, host).get(UpstreamHost::name_data);

        if name != 0 {
            pool.free_locked(name);
        }

        pool.free_locked(host);
    }

    if d.get(RrPeer::server_data) != 0 {
        pool.free_locked(d.get(RrPeer::server_data));
    }

    if d.get(RrPeer::sid_data) != 0 {
        pool.free_locked(d.get(RrPeer::sid_data));
    }

    if d.get(RrPeer::name_data) != 0 {
        pool.free_locked(d.get(RrPeer::name_data));
    }

    if d.get(RrPeer::sockaddr) != 0 {
        pool.free_locked(d.get(RrPeer::sockaddr));
    }

    pool.free_locked(d.off);

    0
}

/// ngx_http_upstream_zone_copy_peer: a peer in the zone, a copy of src (a
/// peer of the memory given) or empty; 0 on failure
pub fn copy_peer(mem: &ShmMem, peers: usize, src: Option<(&ShmMem, usize)>) -> usize {
    let pool = SlabPool::of(mem);

    let dst = pool.calloc_locked(RrPeer::SIZE);
    if dst == 0 {
        return 0;
    }

    let d = RrPeer::at(mem, dst);

    if let Some((smem, src)) = src {
        mem.write(dst, &smem.bytes(src, RrPeer::SIZE));
        d.set(RrPeer::sockaddr, 0);
        d.set(RrPeer::name_data, 0);
        d.set(RrPeer::sid_data, 0);
        d.set(RrPeer::server_data, 0);
        d.set(RrPeer::host, 0);
    }

    d.set(RrPeer::sockaddr, pool.calloc_locked(NGX_SOCKADDRLEN));
    if d.get(RrPeer::sockaddr) == 0 {
        return copy_peer_failed(&pool, d);
    }

    d.set(RrPeer::name_data, pool.calloc_locked(NGX_SOCKADDR_STRLEN));
    if d.get(RrPeer::name_data) == 0 {
        return copy_peer_failed(&pool, d);
    }

    d.set(RrPeer::sid_data, pool.calloc_locked(NGX_HTTP_UPSTREAM_SID_LEN));
    if d.get(RrPeer::sid_data) == 0 {
        return copy_peer_failed(&pool, d);
    }

    if let Some((smem, src)) = src {
        let s = RrPeer::at(smem, src);

        mem.write(d.get(RrPeer::sockaddr), &smem.bytes(s.get(RrPeer::sockaddr), s.get(RrPeer::socklen) as usize));
        mem.write(d.get(RrPeer::name_data), &s.name());
        mem.write(d.get(RrPeer::sid_data), &s.sid());

        let server = pool.alloc_locked(s.get(RrPeer::server_len));
        if server == 0 {
            return copy_peer_failed(&pool, d);
        }

        d.set(RrPeer::server_data, server);
        mem.write(server, &s.server());

        let shost = s.get(RrPeer::host);

        if shost != 0 {
            let sh = UpstreamHost::at(smem, shost);

            let host = pool.calloc_locked(UpstreamHost::SIZE);
            if host == 0 {
                return copy_peer_failed(&pool, d);
            }

            d.set(RrPeer::host, host);

            let h = UpstreamHost::at(mem, host);

            h.set(UpstreamHost::worker, sh.get(UpstreamHost::worker));
            h.set(UpstreamHost::valid, sh.get(UpstreamHost::valid));

            let name = pool.alloc_locked(sh.get(UpstreamHost::name_len));
            if name == 0 {
                return copy_peer_failed(&pool, d);
            }

            h.set(UpstreamHost::name_data, name);

            h.set(UpstreamHost::peers, peers);
            h.set(UpstreamHost::peer, dst);

            h.set(UpstreamHost::name_len, sh.get(UpstreamHost::name_len));
            mem.write(name, &sh.name());

            if sh.get(UpstreamHost::service_len) > 0 {
                let service = pool.alloc_locked(sh.get(UpstreamHost::service_len));
                if service == 0 {
                    return copy_peer_failed(&pool, d);
                }

                h.set(UpstreamHost::service_data, service);
                h.set(UpstreamHost::service_len, sh.get(UpstreamHost::service_len));
                mem.write(service, &sh.service());
            }
        }
    }

    dst
}

/// A peer's address and its printable name (ngx_sock_ntop).
fn set_peer_addr(mem: &ShmMem, peer: usize, sa: &SockAddr) {
    let p = RrPeer::at(mem, peer);

    let bytes = sa.raw_bytes();
    mem.write(p.get(RrPeer::sockaddr), &bytes);
    p.set(RrPeer::socklen, bytes.len() as u32);

    let text = sa.to_text(true);
    let n = text.len().min(NGX_SOCKADDR_STRLEN);
    mem.write(p.get(RrPeer::name_data), &text[..n]);
    p.set(RrPeer::name_len, n);
}

/// A copy of a string in the zone, the data of the peer's server.
fn set_peer_server(mem: &ShmMem, peer: usize, server: &[u8]) -> Result<(), ()> {
    let data = SlabPool::of(mem).alloc(server.len());
    if data == 0 {
        return Err(());
    }

    let p = RrPeer::at(mem, peer);

    mem.write(data, server);
    p.set(RrPeer::server_data, data);
    p.set(RrPeer::server_len, server.len());

    Ok(())
}

/// The parameters of a resolved peer from its template's.
fn set_peer_params(mem: &ShmMem, peer: usize, template: usize, weight: isize) {
    let (p, t) = (RrPeer::at(mem, peer), RrPeer::at(mem, template));

    p.set(RrPeer::weight, weight);
    p.set(RrPeer::effective_weight, weight);
    p.set(RrPeer::max_conns, t.get(RrPeer::max_conns));
    p.set(RrPeer::max_fails, t.get(RrPeer::max_fails));
    p.set(RrPeer::fail_timeout, t.get(RrPeer::fail_timeout));
    p.set(RrPeer::down, t.get(RrPeer::down));
}

/// A peer added to the peers: number, tries, total_weight, weighted.
fn count_peer(mem: &ShmMem, peers: usize, peer: usize) {
    let (ps, p) = (RrPeers::at(mem, peers), RrPeer::at(mem, peer));

    ps.set(RrPeers::number, ps.get(RrPeers::number) + 1);
    ps.set(RrPeers::tries, ps.get(RrPeers::tries) + (p.get(RrPeer::down) == 0) as usize);
    ps.set(RrPeers::total_weight, ps.get(RrPeers::total_weight) + p.get(RrPeer::weight) as usize);
    ps.set(RrPeers::weighted, (ps.get(RrPeers::total_weight) != ps.get(RrPeers::number)) as u8);
}

/// ngx_http_upstream_zone_preresolve: the peers resolved for the servers
/// before a reload (in the zone `omem` of the previous configuration),
/// copied to the new ones
fn preresolve(mem: &ShmMem, resolve: usize, peers: usize, omem: &ShmMem, oresolve: usize, opeers: usize) -> Result<(), ()> {
    if resolve == 0 || oresolve == 0 {
        return Ok(());
    }

    let mut peerp = peers + RrPeers::peer.off;

    while mem.get(peerp) != 0 {
        peerp = mem.get(peerp) + RrPeer::next.off;
    }

    peers_rlock(omem, opeers);

    let mut template = resolve;

    while template != 0 {
        let t = RrPeer::at(mem, template);
        let th = UpstreamHost::at(mem, t.get(RrPeer::host));

        let mut ores = oresolve;

        while ores != 0 {
            let or = RrPeer::at(omem, ores);
            let oh = UpstreamHost::at(omem, or.get(RrPeer::host));

            if oh.name() != th.name() || oh.service() != th.service() {
                ores = or.get(RrPeer::next);
                continue;
            }

            let host = oh.off;

            let mut opeer = RrPeers::at(omem, opeers).get(RrPeers::peer);

            while opeer != 0 {
                let op = RrPeer::at(omem, opeer);

                if op.get(RrPeer::host) != host {
                    opeer = op.get(RrPeer::next);
                    continue;
                }

                let peer = copy_peer(mem, peers, None);
                if peer == 0 {
                    peers_unlock(omem, opeers);
                    return Err(());
                }

                let mut sa = op.addr();

                if th.get(UpstreamHost::service_len) == 0 {
                    let port = t.addr().port();
                    sa.set_port(port);
                }

                set_peer_addr(mem, peer, &sa);

                let p = RrPeer::at(mem, peer);

                p.set(RrPeer::host, t.get(RrPeer::host));

                th.set(UpstreamHost::valid, oh.get(UpstreamHost::valid));

                let server = if th.get(UpstreamHost::service_len) > 0 { op.server() } else { t.server() };

                if set_peer_server(mem, peer, &server).is_err() {
                    peers_unlock(omem, opeers);
                    return Err(());
                }

                let weight = if oh.get(UpstreamHost::service_len) == 0 {
                    t.get(RrPeer::weight)
                } else if t.get(RrPeer::weight) != 1 {
                    t.get(RrPeer::weight)
                } else {
                    op.get(RrPeer::weight)
                };

                set_peer_params(mem, peer, template, weight);

                copy_round_robin_sid(mem, peer, template);

                config_inc(mem, RrPeers::at(mem, peers).get(RrPeers::config));

                mem.set(peerp, peer);
                peerp = peer + RrPeer::next.off;

                count_peer(mem, peers, peer);

                opeer = op.get(RrPeer::next);
            }

            break;
        }

        template = t.get(RrPeer::next);
    }

    peers_unlock(omem, opeers);

    Ok(())
}

/// ngx_http_upstream_zone_set_single
fn set_single(uscf: &UpstreamSrvConf) {
    let Peers { mem: pm, off: peers } = match uscf.peers.get() {
        Some(p) => p,
        None => return,
    };
    let mem = &*pm.mem;

    let ps = RrPeers::at(mem, peers);
    let next = ps.get(RrPeers::next);

    let single = ps.get(RrPeers::number) == 1 && (next == 0 || RrPeers::at(mem, next).get(RrPeers::number) == 0);

    ps.set(RrPeers::single, single as u8);
}

/// ngx_http_upstream_zone_remove_peer_locked
fn remove_peer_locked(mem: &ShmMem, peers: usize, peer: usize) {
    let (ps, p) = (RrPeers::at(mem, peers), RrPeer::at(mem, peer));

    ps.set(RrPeers::total_weight, ps.get(RrPeers::total_weight).wrapping_sub(p.get(RrPeer::weight) as usize));
    ps.set(RrPeers::number, ps.get(RrPeers::number).wrapping_sub(1));
    ps.set(RrPeers::tries, ps.get(RrPeers::tries).wrapping_sub((p.get(RrPeer::down) == 0) as usize));
    config_inc(mem, ps.get(RrPeers::config));
    ps.set(RrPeers::weighted, (ps.get(RrPeers::total_weight) != ps.get(RrPeers::number)) as u8);

    peer_free(mem, peers, peer);
}

/// ngx_http_upstream_zone_init_worker: the resolve timers of the servers
/// of the worker
fn init_worker(cycle: &Rc<ngx_core::cycle::Cycle>) -> Result<(), ()> {
    let process = ngx_core::cycle::globals(|g| g.process);

    if process != ngx_core::cycle::ProcessType::Worker && process != ngx_core::cycle::ProcessType::Single {
        return Ok(());
    }

    let worker = if process == ngx_core::cycle::ProcessType::Worker { ngx_core::event::worker_index() as usize } else { 0 };

    let now = ngx_core::times::time();

    let umcf = match crate::cycle_main_conf::<UpstreamMainConf>(cycle, crate::upstream::ctx_index) {
        Some(umcf) => umcf,
        None => return Ok(()),
    };

    let upstreams = umcf.borrow().upstreams.borrow().clone();

    for uscf in upstreams.iter() {
        if uscf.shm_zone.borrow().is_none() {
            continue;
        }

        let Peers { mem: pm, off: mut peers } = match uscf.peers.get() {
            Some(p) => p,
            None => continue,
        };
        let mem = &*pm.mem;

        while peers != 0 {
            peers_wlock(mem, peers);

            let mut peer = RrPeers::at(mem, peers).get(RrPeers::resolve);

            while peer != 0 {
                let host = RrPeer::at(mem, peer).get(RrPeer::host);
                let h = UpstreamHost::at(mem, host);

                if h.get(UpstreamHost::worker) == worker {
                    let valid = h.get(UpstreamHost::valid);

                    let timer = if valid > now { 1000 * (valid - now) as u64 } else { 1 };

                    let uscf = uscf.clone();
                    let pm = pm.clone();

                    ngx_core::event::spawn_posted(async move {
                        resolve_loop(uscf, pm, host, timer).await;
                    });
                }

                peer = RrPeer::at(mem, peer).get(RrPeer::next);
            }

            peers_unlock(mem, peers);

            peers = RrPeers::at(mem, peers).get(RrPeers::next);
        }
    }

    Ok(())
}

/// The resolve timer of a host: ngx_http_upstream_zone_resolve_timer, then
/// again after the handler's time.
async fn resolve_loop(uscf: Rc<UpstreamSrvConf>, pm: Rc<PeerMem>, host: usize, first: u64) {
    let mut timer = first;

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(timer)).await;

        ngx_core::times::update();

        timer = match resolve_timer(&uscf, &pm.mem, host).await {
            Some(t) => t,
            None => return,
        };
    }
}

fn cycle_log() -> Log {
    ngx_core::cycle::cycle().log.clone()
}

/// ngx_http_upstream_zone_resolve_timer: the time of the next resolve, or
/// None when there is no resolver
async fn resolve_timer(uscf: &Rc<UpstreamSrvConf>, mem: &ShmMem, host: usize) -> Option<u64> {
    let resolver = uscf.resolver.borrow().clone().unwrap_or_else(Resolver::empty);
    let resolver_timeout = uscf.resolver_timeout.get().unwrap_or(30000);

    let h = UpstreamHost::at(mem, host);
    let (name, service) = (h.name(), h.service());

    match resolver.resolve(&name, &service, resolver_timeout).await {
        Resolved::NoResolver => {
            ngx_log_error!(NGX_LOG_ERR, cycle_log(), None, "no resolver defined to resolve {}", B(&name));
            None
        }

        // retry:
        Resolved::Error => Some(resolver_timeout.max(1000)),

        Resolved::Done(g) => Some(resolve_handler(uscf, mem, host, &g.ctx)),
    }
}

/// ngx_cmp_sockaddr: the same address, and port if asked
fn cmp_sockaddr(a: &SockAddr, b: &SockAddr, cmp_port: bool) -> bool {
    match (a, b) {
        (SockAddr::V4(x), SockAddr::V4(y)) => (!cmp_port || x.port() == y.port()) && x.ip() == y.ip(),
        (SockAddr::V6(x), SockAddr::V6(y)) => (!cmp_port || x.port() == y.port()) && x.ip() == y.ip(),
        (SockAddr::Unix(x), SockAddr::Unix(y)) => x == y,
        _ => false,
    }
}

/// ngx_http_upstream_zone_resolve_handler: the peers of the host are the
/// addresses resolved; the time of the next resolve
fn resolve_handler(uscf: &Rc<UpstreamSrvConf>, mem: &ShmMem, host: usize, ctx: &Rc<ResolverCtx>) -> u64 {
    let log = cycle_log();

    let h = UpstreamHost::at(mem, host);

    let mut peers = h.get(UpstreamHost::peers);
    let template = h.get(UpstreamHost::peer);
    let t = RrPeer::at(mem, template);

    peers_wlock(mem, peers);

    let now = ngx_core::times::time();

    let service = h.service();

    for srv in ctx.srvs.borrow().iter() {
        if srv.state != 0 {
            ngx_log_error!(
                NGX_LOG_ERR,
                log,
                None,
                "{} could not be resolved ({}: {}) while resolving service {} of {}",
                B(&srv.name),
                srv.state,
                Resolver::strerror(srv.state),
                B(&ctx.service.borrow()),
                B(&ctx.name.borrow())
            );
        }
    }

    let mut addrs = ctx.addrs.borrow().clone();

    let state = ctx.state.get();

    if state != 0 {
        if !service.is_empty() {
            ngx_log_error!(
                NGX_LOG_ERR,
                log,
                None,
                "service {} of {} could not be resolved ({}: {})",
                B(&ctx.service.borrow()),
                B(&ctx.name.borrow()),
                state,
                Resolver::strerror(state)
            );
        } else {
            ngx_log_error!(NGX_LOG_ERR, log, None, "{} could not be resolved ({}: {})", B(&ctx.name.borrow()), state, Resolver::strerror(state));
        }

        if state != NGX_RESOLVE_NXDOMAIN {
            peers_unlock(mem, peers);

            return uscf.resolver_timeout.get().unwrap_or(30000).max(1000);
        }

        // NGX_RESOLVE_NXDOMAIN

        addrs.clear();
    }

    let mut backup = false;
    let min_priority = addrs.iter().map(|a| a.priority).min().unwrap_or(65535);

    for a in addrs.iter() {
        ngx_log_debug!(
            NGX_LOG_DEBUG_HTTP,
            log,
            "name {} was resolved to {} s:\"{}\" n:\"{}\" w:{} {}",
            B(&h.name()),
            B(&a.sockaddr.to_text(true)),
            B(&service),
            B(&a.name),
            a.weight,
            if a.priority != min_priority { "backup" } else { "" }
        );
    }

    let mut marked = vec![false; addrs.len()];

    'done: loop {
        // again:

        let mut peerp = peers + RrPeers::peer.off;

        loop {
            let peer = mem.get(peerp);

            if peer == 0 {
                break;
            }

            let p = RrPeer::at(mem, peer);

            if p.get(RrPeer::host) != host {
                peerp = peer + RrPeer::next.off;
                continue;
            }

            let psa = p.addr();

            let mut found = false;

            for (j, addr) in addrs.iter().enumerate() {
                let addr_backup = addr.priority != min_priority;
                if addr_backup != backup {
                    continue;
                }

                if marked[j] {
                    continue;
                }

                if !cmp_sockaddr(&psa, &addr.sockaddr, !service.is_empty()) {
                    continue;
                }

                if !service.is_empty() {
                    if addr.name.len() != p.get(RrPeer::server_len) || !mem.eq_bytes(p.get(RrPeer::server_data), &addr.name) {
                        continue;
                    }

                    if t.get(RrPeer::weight) == 1 && addr.weight as isize != p.get(RrPeer::weight) {
                        continue;
                    }
                }

                marked[j] = true;
                found = true;
                break;
            }

            if found {
                // next:
                peerp = peer + RrPeer::next.off;
                continue;
            }

            mem.set(peerp, p.get(RrPeer::next));
            remove_peer_locked(mem, peers, peer);

            set_single(uscf);
        }

        for (i, addr) in addrs.iter().enumerate() {
            let addr_backup = addr.priority != min_priority;
            if addr_backup != backup {
                continue;
            }

            if marked[i] {
                marked[i] = false;
                continue;
            }

            let pool = SlabPool::of(mem);

            pool.lock();
            let peer = copy_peer(mem, peers, None);
            pool.unlock();

            if peer == 0 {
                ngx_log_error!(
                    NGX_LOG_ERR,
                    log,
                    None,
                    "cannot add new server to upstream \"{}\", memory exhausted",
                    B(&RrPeers::at(mem, peers).name_bytes())
                );
                break 'done;
            }

            let mut sa = addr.sockaddr.clone();

            if service.is_empty() {
                let port = t.addr().port();
                sa.set_port(port);
            }

            set_peer_addr(mem, peer, &sa);

            let p = RrPeer::at(mem, peer);

            p.set(RrPeer::host, t.get(RrPeer::host));

            let server = if !service.is_empty() { addr.name.clone() } else { t.server() };

            if set_peer_server(mem, peer, &server).is_err() {
                peer_free(mem, peers, peer);

                ngx_log_error!(
                    NGX_LOG_ERR,
                    log,
                    None,
                    "cannot add new server to upstream \"{}\", memory exhausted",
                    B(&RrPeers::at(mem, peers).name_bytes())
                );
                break 'done;
            }

            let weight = if service.is_empty() {
                t.get(RrPeer::weight)
            } else if t.get(RrPeer::weight) != 1 {
                t.get(RrPeer::weight)
            } else {
                addr.weight as isize
            };

            set_peer_params(mem, peer, template, weight);

            copy_round_robin_sid(mem, peer, template);

            mem.set(peerp, peer);
            peerp = peer + RrPeer::next.off;

            count_peer(mem, peers, peer);
            config_inc(mem, RrPeers::at(mem, peers).get(RrPeers::config));

            set_single(uscf);
        }

        let next = RrPeers::at(mem, peers).get(RrPeers::next);

        if !service.is_empty() && next != 0 {
            peers_unlock(mem, peers);

            peers = next;
            backup = true;

            peers_wlock(mem, peers);

            continue;
        }

        break;
    }

    // done:

    let valid = ctx.valid.get();

    h.set(UpstreamHost::valid, valid);

    peers_unlock(mem, peers);

    1000 * (if valid > now { valid - now + 1 } else { 1 }) as u64
}

pub fn upstream_zone_module() -> ModuleDef {
    let commands = vec![cmd_fn!("zone", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE12, ConfLevel::None, zone_handler)];
    let mut m = http_module_def("ngx_http_upstream_zone_module", HttpModuleDef::default(), commands);
    m.init_process = Some(init_worker);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    use ngx_core::inet::Addr;
    use ngx_core::rc::NGX_DONE;

    fn server(name: &str, addrs: &[(&str, u16)], weight: u32) -> UpstreamServer {
        UpstreamServer {
            name: name.as_bytes().to_vec(),
            addrs: addrs
                .iter()
                .map(|(ip, port)| {
                    let sa = SockAddr::v4(ip.parse().unwrap(), *port);
                    Addr { name: sa.to_text(true), sockaddr: sa }
                })
                .collect(),
            weight,
            max_fails: 1,
            fail_timeout: 10,
            ..Default::default()
        }
    }

    /// A zone of a process, its slab pool made.
    fn zone_mem(size: usize) -> Rc<PeerMem> {
        let mem = Rc::new(ShmMem::private(size).unwrap());
        SlabPool::init_zone(&mem);
        PeerMem::zone(mem)
    }

    /// The peers of all the peers' lists: (server, name, weight).
    fn list(mem: &ShmMem, peers: usize) -> Vec<(Vec<u8>, Vec<u8>, isize)> {
        let mut out = Vec::new();
        let mut peer = RrPeers::at(mem, peers).get(RrPeers::peer);
        while peer != 0 {
            let p = RrPeer::at(mem, peer);
            out.push((p.server(), p.name(), p.get(RrPeer::weight)));
            peer = p.get(RrPeer::next);
        }
        out
    }

    #[test]
    fn copied_to_the_zone_and_freed() {
        let pm = PeerMem::process(64 << 10).unwrap();
        let name = {
            let n = pm.alloc(NgxStr::SIZE);
            let s = NgxStr::at(&pm.mem, n);
            s.set(NgxStr::data, pm.dup(b"backend"));
            s.set(NgxStr::len, 7);
            n
        };

        // two peers of the process, as init_round_robin makes them
        let srcs = [server("a", &[("127.0.0.1", 8081)], 2), server("b", &[("127.0.0.2", 8082)], 1)];
        let src_peers = {
            let peers = pm.alloc(RrPeers::SIZE);
            let ps = RrPeers::at(&pm.mem, peers);
            ps.set(RrPeers::number, 2);
            ps.set(RrPeers::total_weight, 3);
            ps.set(RrPeers::tries, 2);
            ps.set(RrPeers::weighted, 1);
            ps.set(RrPeers::name, name);
            let mut peerp = peers + RrPeers::peer.off;
            for s in srcs.iter() {
                let p = pm.alloc(RrPeer::SIZE);
                let pp = RrPeer::at(&pm.mem, p);
                let sa = s.addrs[0].sockaddr.raw_bytes();
                pp.set(RrPeer::sockaddr, pm.dup(&sa));
                pp.set(RrPeer::socklen, sa.len() as u32);
                pp.set(RrPeer::name_data, pm.dup(&s.addrs[0].name));
                pp.set(RrPeer::name_len, s.addrs[0].name.len());
                pp.set(RrPeer::server_data, pm.dup(&s.name));
                pp.set(RrPeer::server_len, s.name.len());
                pp.set(RrPeer::weight, s.weight as isize);
                pp.set(RrPeer::sid_data, pm.alloc(32));
                init_round_robin_sid(&pm.mem, p, None);
                pm.mem.set(peerp, p);
                peerp = p + RrPeer::next.off;
            }
            peers
        };

        let zm = zone_mem(256 << 10);
        let mem = &*zm.mem;
        let pool = SlabPool::of(mem);
        let pfree = pool.pfree();

        let config = pool.calloc(8);
        let peers = pool.alloc(RrPeers::SIZE);
        mem.write(peers, &pm.mem.bytes(src_peers, RrPeers::SIZE));
        RrPeers::at(mem, peers).set(RrPeers::shpool, 1);
        RrPeers::at(mem, peers).set(RrPeers::config, config);
        RrPeers::at(mem, peers).set(RrPeers::name, 0);

        copy_list(mem, &pm.mem, peers, peers + RrPeers::peer.off).unwrap();
        assert_eq!(mem.get(config), 2);

        let got = list(mem, peers);
        assert_eq!(got, vec![(b"a".to_vec(), b"127.0.0.1:8081".to_vec(), 2), (b"b".to_vec(), b"127.0.0.2:8082".to_vec(), 1)]);

        let first = RrPeers::at(mem, peers).get(RrPeers::peer);
        let p = RrPeer::at(mem, first);
        assert_eq!(p.addr(), SockAddr::v4("127.0.0.1".parse().unwrap(), 8081));
        assert_eq!(p.sid(), RrPeer::at(&pm.mem, RrPeers::at(&pm.mem, src_peers).get(RrPeers::peer)).sid());

        // a peer referenced is a zombie, freed with its last reference
        peer_ref(mem, first);
        let second = p.get(RrPeer::next);
        RrPeers::at(mem, peers).set(RrPeers::peer, second);
        remove_peer_locked(mem, peers, first);
        assert_eq!(p.get(RrPeer::zombie), 1);
        assert_eq!(RrPeers::at(mem, peers).get(RrPeers::number), 1);
        assert_eq!(RrPeers::at(mem, peers).get(RrPeers::total_weight), 1);
        assert_eq!(mem.get(config), 3);
        assert_eq!(peer_unref(mem, peers, first), NGX_DONE);

        RrPeers::at(mem, peers).set(RrPeers::peer, 0);
        remove_peer_locked(mem, peers, second);

        pool.free(peers);
        pool.free(config);
        assert_eq!(pool.pfree(), pfree, "all the zone's memory is back");
    }

    #[test]
    fn resolved_peers_from_a_template() {
        let zm = zone_mem(256 << 10);
        let mem = &*zm.mem;
        let pool = SlabPool::of(mem);

        let config = pool.calloc(8);
        let peers = pool.calloc(RrPeers::SIZE);
        let ps = RrPeers::at(mem, peers);
        ps.set(RrPeers::shpool, 1);
        ps.set(RrPeers::config, config);

        // the template: "server example.com:8080 resolve weight=3"
        let template = copy_peer(mem, peers, None);
        set_peer_addr(mem, template, &SockAddr::v4("0.0.0.0".parse().unwrap(), 8080));
        set_peer_server(mem, template, b"example.com:8080").unwrap();
        RrPeer::at(mem, template).set(RrPeer::weight, 3);
        RrPeer::at(mem, template).set(RrPeer::max_fails, 2);
        init_round_robin_sid(mem, template, Some(b"rt"));

        let peer = copy_peer(mem, peers, None);
        let mut sa = SockAddr::v4("192.0.2.1".parse().unwrap(), 53);
        sa.set_port(RrPeer::at(mem, template).addr().port());
        set_peer_addr(mem, peer, &sa);
        set_peer_server(mem, peer, &RrPeer::at(mem, template).server()).unwrap();
        set_peer_params(mem, peer, template, 3);
        copy_round_robin_sid(mem, peer, template);
        ps.set(RrPeers::peer, peer);
        count_peer(mem, peers, peer);

        let p = RrPeer::at(mem, peer);
        assert_eq!(p.name(), b"192.0.2.1:8080");
        assert_eq!(p.server(), b"example.com:8080");
        assert_eq!(p.get(RrPeer::max_fails), 2);
        assert_eq!(p.get(RrPeer::effective_weight), 3);
        assert_eq!(p.sid(), b"rt");
        assert_eq!(ps.get(RrPeers::number), 1);
        assert_eq!(ps.get(RrPeers::tries), 1);
        assert_eq!(ps.get(RrPeers::total_weight), 3);
        assert_eq!(ps.get(RrPeers::weighted), 1);
    }

    #[test]
    fn copy_fails_without_memory() {
        // a zone of 8 pages: copies until there is no more room, each
        // failure giving back what it took
        let zm = zone_mem(8 * 4096);
        let mem = &*zm.mem;
        let pool = SlabPool::of(mem);
        pool.set_log_nomem(false);

        let peers = pool.calloc(RrPeers::SIZE);
        let mut n = 0;
        loop {
            if copy_peer(mem, peers, None) == 0 {
                break;
            }
            n += 1;
            assert!(n < 1000);
        }
        assert!(n > 0);
        assert_eq!(copy_peer(mem, peers, None), 0, "still no room: what failed was given back");
    }
}
