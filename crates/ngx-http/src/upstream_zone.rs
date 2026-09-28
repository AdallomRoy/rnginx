//! ngx_http_upstream_zone_module: "zone name [size]". The peers of the
//! upstreams in a zone are copied to its shared memory, shared by the
//! workers; servers with "resolve" are resolved there at run time by
//! worker 0, and after a reload the new peers start with the addresses
//! resolved before (preresolve).

use std::any::Any;
use std::cell::RefCell;
use std::ptr::null_mut;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::inet::SockAddr;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::resolver::{ResolverCtx, Resolved, Resolver, NGX_RESOLVE_NXDOMAIN};
use ngx_core::shm::ShmZone;
use ngx_core::slab::SlabPool;
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
    let shpool = shm_zone.shm.addr.get() as *mut SlabPool;

    let umcf = zone_umcf(&shm_zone.data.borrow()).ok_or(())?;
    let upstreams = umcf.borrow().upstreams.borrow().clone();

    let in_zone = |uscf: &Rc<UpstreamSrvConf>| uscf.shm_zone.borrow().as_ref().is_some_and(|z| Rc::ptr_eq(z, shm_zone));

    unsafe {
        if shm_zone.shm.exists.get() {
            let mut peers = (*shpool).data as *mut RrPeers;

            for uscf in upstreams.iter().filter(|u| in_zone(u)) {
                uscf.peers.set(peers);
                peers = (*peers).zone_next;
            }

            return Ok(());
        }

        let ctx = format!(" in upstream zone \"{}\"", B(shm_zone.name()));
        (*shpool).set_log_ctx(ctx.as_bytes())?;

        // copy peers to shared memory

        let mut peersp: *mut *mut RrPeers = &mut (*shpool).data as *mut *mut u8 as *mut *mut RrPeers;

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

            let peers = copy_peers(shpool, uscf, ouscf.as_ref());
            if peers.is_null() {
                return Err(());
            }

            *peersp = peers;
            peersp = &mut (*peers).zone_next;
        }
    }

    Ok(())
}

/// A copy of bytes in the zone.
unsafe fn shm_dup(pool: &SlabPool, s: &[u8], locked: bool) -> Option<NgxStr> {
    if s.is_empty() {
        return Some(NgxStr::NULL);
    }

    let p = if locked { pool.alloc_locked(s.len()) } else { pool.alloc(s.len()) };
    if p.is_null() {
        return None;
    }

    std::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());

    Some(NgxStr { data: p, len: s.len() })
}

/// ngx_http_upstream_zone_copy_peers
unsafe fn copy_peers(shpool: *mut SlabPool, uscf: &Rc<UpstreamSrvConf>, ouscf: Option<&Rc<UpstreamSrvConf>>) -> *mut RrPeers {
    let pool = &*shpool;

    let opeers = ouscf.map_or(null_mut(), |o| o.peers.get());

    let config = pool.calloc(std::mem::size_of::<usize>()) as *mut usize;
    if config.is_null() {
        return null_mut();
    }

    let peers = pool.alloc(std::mem::size_of::<RrPeers>()) as *mut RrPeers;
    if peers.is_null() {
        return null_mut();
    }

    std::ptr::copy_nonoverlapping(uscf.peers.get() as *const RrPeers, peers, 1);

    let name = pool.alloc(std::mem::size_of::<NgxStr>()) as *mut NgxStr;
    if name.is_null() {
        return null_mut();
    }

    *name = match shm_dup(pool, (*(*peers).name).bytes(), false) {
        Some(s) => s,
        None => return null_mut(),
    };

    (*peers).name = name;

    (*peers).shpool = shpool;
    (*peers).config = config;

    if copy_list(peers, &mut (*peers).peer).is_err() {
        return null_mut();
    }

    if copy_list(peers, &mut (*peers).resolve).is_err() {
        return null_mut();
    }

    if !opeers.is_null() && preresolve((*peers).resolve, peers, (*opeers).resolve, opeers).is_err() {
        return null_mut();
    }

    if !(*peers).next.is_null() {
        let backup = pool.alloc(std::mem::size_of::<RrPeers>()) as *mut RrPeers;
        if backup.is_null() {
            return null_mut();
        }

        std::ptr::copy_nonoverlapping((*peers).next as *const RrPeers, backup, 1);

        (*backup).name = name;

        (*backup).shpool = shpool;
        (*backup).config = config;

        if copy_list(backup, &mut (*backup).peer).is_err() {
            return null_mut();
        }

        if copy_list(backup, &mut (*backup).resolve).is_err() {
            return null_mut();
        }

        (*peers).next = backup;

        if !opeers.is_null() && !(*opeers).next.is_null() {
            if preresolve((*peers).resolve, backup, (*opeers).resolve, (*opeers).next).is_err() {
                return null_mut();
            }

            if preresolve((*backup).resolve, backup, (*(*opeers).next).resolve, (*opeers).next).is_err() {
                return null_mut();
            }
        }
    }

    // done:

    uscf.peers.set(peers);

    set_single(uscf);

    peers
}

/// The peers of a list copied, each counted in the zone's config.
unsafe fn copy_list(peers: *mut RrPeers, mut peerp: *mut *mut RrPeer) -> Result<(), ()> {
    while !(*peerp).is_null() {
        // pool is unlocked
        let peer = copy_peer(peers, *peerp);
        if peer.is_null() {
            return Err(());
        }

        *peerp = peer;
        *(*peers).config += 1;

        peerp = &mut (*peer).next;
    }

    Ok(())
}

/// ngx_http_upstream_zone_copy_peer: a peer in the zone, a copy of src or
/// empty
pub unsafe fn copy_peer(peers: *mut RrPeers, src: *mut RrPeer) -> *mut RrPeer {
    let pool = &*(*peers).shpool;

    let dst = pool.calloc_locked(std::mem::size_of::<RrPeer>()) as *mut RrPeer;
    if dst.is_null() {
        return null_mut();
    }

    if !src.is_null() {
        std::ptr::copy_nonoverlapping(src as *const RrPeer, dst, 1);
        (*dst).sockaddr = null_mut();
        (*dst).name.data = null_mut();
        (*dst).sid.data = null_mut();
        (*dst).server.data = null_mut();
        (*dst).host = null_mut();
    }

    let failed = |dst: *mut RrPeer| {
        if !(*dst).host.is_null() {
            if !(*(*dst).host).name.data.is_null() {
                pool.free_locked((*(*dst).host).name.data);
            }

            pool.free_locked((*dst).host as *mut u8);
        }

        if !(*dst).server.data.is_null() {
            pool.free_locked((*dst).server.data);
        }

        if !(*dst).sid.data.is_null() {
            pool.free_locked((*dst).sid.data);
        }

        if !(*dst).name.data.is_null() {
            pool.free_locked((*dst).name.data);
        }

        if !(*dst).sockaddr.is_null() {
            pool.free_locked((*dst).sockaddr as *mut u8);
        }

        pool.free_locked(dst as *mut u8);

        null_mut()
    };

    (*dst).sockaddr = pool.calloc_locked(std::mem::size_of::<libc::sockaddr_storage>()) as *mut libc::sockaddr;
    if (*dst).sockaddr.is_null() {
        return failed(dst);
    }

    (*dst).name.data = pool.calloc_locked(NGX_SOCKADDR_STRLEN);
    if (*dst).name.data.is_null() {
        return failed(dst);
    }

    (*dst).sid.data = pool.calloc_locked(NGX_HTTP_UPSTREAM_SID_LEN);
    if (*dst).sid.data.is_null() {
        return failed(dst);
    }

    if !src.is_null() {
        std::ptr::copy_nonoverlapping((*src).sockaddr as *const u8, (*dst).sockaddr as *mut u8, (*src).socklen as usize);
        std::ptr::copy_nonoverlapping((*src).name.data, (*dst).name.data, (*src).name.len);
        if (*src).sid.len > 0 {
            std::ptr::copy_nonoverlapping((*src).sid.data, (*dst).sid.data, (*src).sid.len);
        }

        (*dst).server = match shm_dup(pool, (*src).server.bytes(), true) {
            Some(s) => s,
            None => return failed(dst),
        };

        if !(*src).host.is_null() {
            (*dst).host = pool.calloc_locked(std::mem::size_of::<UpstreamHost>()) as *mut UpstreamHost;
            if (*dst).host.is_null() {
                return failed(dst);
            }

            let host = (*dst).host;
            let shost = (*src).host;

            (*host).worker = (*shost).worker;
            (*host).valid = (*shost).valid;

            (*host).name = match shm_dup(pool, (*shost).name.bytes(), true) {
                Some(s) => s,
                None => return failed(dst),
            };

            (*host).peers = peers;
            (*host).peer = dst;

            if (*shost).service.len > 0 {
                (*host).service = match shm_dup(pool, (*shost).service.bytes(), true) {
                    Some(s) => s,
                    None => return failed(dst),
                };
            }
        }
    }

    dst
}

/// Set a peer's address and its printable name (ngx_sock_ntop).
unsafe fn set_peer_addr(peer: *mut RrPeer, sa: &SockAddr) {
    let (ss, len) = sa.to_libc();
    std::ptr::copy_nonoverlapping(&ss as *const libc::sockaddr_storage as *const u8, (*peer).sockaddr as *mut u8, len as usize);
    (*peer).socklen = len;

    let text = sa.to_text(true);
    let n = text.len().min(NGX_SOCKADDR_STRLEN);
    std::ptr::copy_nonoverlapping(text.as_ptr(), (*peer).name.data, n);
    (*peer).name.len = n;
}

/// ngx_http_upstream_zone_preresolve: the peers resolved for the servers
/// before a reload, copied to the new ones
unsafe fn preresolve(resolve: *mut RrPeer, peers: *mut RrPeers, oresolve: *mut RrPeer, opeers: *mut RrPeers) -> Result<(), ()> {
    if resolve.is_null() || oresolve.is_null() {
        return Ok(());
    }

    let mut peerp: *mut *mut RrPeer = &mut (*peers).peer;

    while !(*peerp).is_null() {
        peerp = &mut (**peerp).next;
    }

    peers_rlock(opeers);

    let mut template = resolve;

    while !template.is_null() {
        let mut ores = oresolve;

        while !ores.is_null() {
            if (*(*ores).host).name.bytes() != (*(*template).host).name.bytes() || (*(*ores).host).service.bytes() != (*(*template).host).service.bytes() {
                ores = (*ores).next;
                continue;
            }

            let host = (*ores).host;

            let mut opeer = (*opeers).peer;

            while !opeer.is_null() {
                if (*opeer).host != host {
                    opeer = (*opeer).next;
                    continue;
                }

                let pool = &*(*peers).shpool;

                let peer = copy_peer(peers, null_mut());
                if peer.is_null() {
                    peers_unlock(opeers);
                    return Err(());
                }

                let mut sa = peer_sockaddr(opeer);

                if (*(*template).host).service.len == 0 {
                    let port = peer_sockaddr(template).port();
                    sa.set_port(port);
                }

                set_peer_addr(peer, &sa);

                (*peer).host = (*template).host;

                (*(*template).host).valid = (*host).valid;

                let server = if (*(*template).host).service.len > 0 { (*opeer).server.bytes() } else { (*template).server.bytes() };

                (*peer).server = match shm_dup(pool, server, false) {
                    Some(s) => s,
                    None => {
                        peers_unlock(opeers);
                        return Err(());
                    }
                };

                (*peer).weight = if (*host).service.len == 0 {
                    (*template).weight
                } else if (*template).weight != 1 {
                    (*template).weight
                } else {
                    (*opeer).weight
                };

                (*peer).effective_weight = (*peer).weight;
                (*peer).max_conns = (*template).max_conns;
                (*peer).max_fails = (*template).max_fails;
                (*peer).fail_timeout = (*template).fail_timeout;
                (*peer).down = (*template).down;

                copy_round_robin_sid(peer, template);

                *(*peers).config += 1;

                *peerp = peer;
                peerp = &mut (*peer).next;

                (*peers).number += 1;
                (*peers).tries += ((*peer).down == 0) as usize;
                (*peers).total_weight += (*peer).weight as usize;
                (*peers).weighted = (*peers).total_weight != (*peers).number;

                opeer = (*opeer).next;
            }

            break;
        }

        template = (*template).next;
    }

    peers_unlock(opeers);

    Ok(())
}

/// ngx_http_upstream_zone_set_single
fn set_single(uscf: &UpstreamSrvConf) {
    let peers = uscf.peers.get();

    unsafe {
        (*peers).single = (*peers).number == 1 && ((*peers).next.is_null() || (*(*peers).next).number == 0);
    }
}

/// ngx_http_upstream_zone_remove_peer_locked
unsafe fn remove_peer_locked(peers: *mut RrPeers, peer: *mut RrPeer) {
    (*peers).total_weight -= (*peer).weight as usize;
    (*peers).number -= 1;
    (*peers).tries -= ((*peer).down == 0) as usize;
    *(*peers).config += 1;
    (*peers).weighted = (*peers).total_weight != (*peers).number;

    peer_free(peers, peer);
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

        let mut peers = uscf.peers.get();

        unsafe {
            while !peers.is_null() {
                peers_wlock(peers);

                let mut peer = (*peers).resolve;

                while !peer.is_null() {
                    let host = (*peer).host;

                    if (*host).worker == worker {
                        let timer = if (*host).valid > now { 1000 * ((*host).valid - now) as u64 } else { 1 };

                        let uscf = uscf.clone();
                        let host = host as usize;

                        ngx_core::event::spawn_posted(async move {
                            resolve_loop(uscf, host as *mut UpstreamHost, timer).await;
                        });
                    }

                    peer = (*peer).next;
                }

                peers_unlock(peers);

                peers = (*peers).next;
            }
        }
    }

    Ok(())
}

/// The resolve timer of a host: ngx_http_upstream_zone_resolve_timer, then
/// again after the handler's time.
async fn resolve_loop(uscf: Rc<UpstreamSrvConf>, host: *mut UpstreamHost, first: u64) {
    let mut timer = first;

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(timer)).await;

        ngx_core::times::update();

        timer = match resolve_timer(&uscf, host).await {
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
async fn resolve_timer(uscf: &Rc<UpstreamSrvConf>, host: *mut UpstreamHost) -> Option<u64> {
    let resolver = uscf.resolver.borrow().clone().unwrap_or_else(Resolver::empty);
    let resolver_timeout = uscf.resolver_timeout.get().unwrap_or(30000);

    let (name, service) = unsafe { ((*host).name.bytes().to_vec(), (*host).service.bytes().to_vec()) };

    match resolver.resolve(&name, &service, resolver_timeout).await {
        Resolved::NoResolver => {
            ngx_log_error!(NGX_LOG_ERR, cycle_log(), None, "no resolver defined to resolve {}", B(&name));
            None
        }

        // retry:
        Resolved::Error => Some(resolver_timeout.max(1000)),

        Resolved::Done(g) => Some(unsafe { resolve_handler(uscf, host, &g.ctx) }),
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
unsafe fn resolve_handler(uscf: &Rc<UpstreamSrvConf>, host: *mut UpstreamHost, ctx: &Rc<ResolverCtx>) -> u64 {
    let log = cycle_log();

    let mut peers = (*host).peers;
    let template = (*host).peer;

    peers_wlock(peers);

    let now = ngx_core::times::time();

    let service = (*host).service.bytes();

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
            peers_unlock(peers);

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
            B((*host).name.bytes()),
            B(&a.sockaddr.to_text(true)),
            B(service),
            B(&a.name),
            a.weight,
            if a.priority != min_priority { "backup" } else { "" }
        );
    }

    let mut marked = vec![false; addrs.len()];

    'done: loop {
        // again:

        let mut peerp: *mut *mut RrPeer = &mut (*peers).peer;

        while !(*peerp).is_null() {
            let peer = *peerp;

            if (*peer).host != host {
                peerp = &mut (*peer).next;
                continue;
            }

            let psa = peer_sockaddr(peer);

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
                    if addr.name.as_slice() != (*peer).server.bytes() {
                        continue;
                    }

                    if (*template).weight == 1 && addr.weight as isize != (*peer).weight {
                        continue;
                    }
                }

                marked[j] = true;
                found = true;
                break;
            }

            if found {
                // next:
                peerp = &mut (*peer).next;
                continue;
            }

            *peerp = (*peer).next;
            remove_peer_locked(peers, peer);

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

            let pool = &*(*peers).shpool;

            pool.lock();
            let peer = copy_peer(peers, null_mut());
            pool.unlock();

            if peer.is_null() {
                ngx_log_error!(NGX_LOG_ERR, log, None, "cannot add new server to upstream \"{}\", memory exhausted", B((*(*peers).name).bytes()));
                break 'done;
            }

            let mut sa = addr.sockaddr.clone();

            if service.is_empty() {
                let port = peer_sockaddr(template).port();
                sa.set_port(port);
            }

            set_peer_addr(peer, &sa);

            (*peer).host = (*template).host;

            let server = if !service.is_empty() { addr.name.as_slice() } else { (*template).server.bytes() };

            (*peer).server = match shm_dup(pool, server, false) {
                Some(s) => s,
                None => {
                    peer_free(peers, peer);

                    ngx_log_error!(NGX_LOG_ERR, log, None, "cannot add new server to upstream \"{}\", memory exhausted", B((*(*peers).name).bytes()));
                    break 'done;
                }
            };

            (*peer).weight = if service.is_empty() {
                (*template).weight
            } else if (*template).weight != 1 {
                (*template).weight
            } else {
                addr.weight as isize
            };

            (*peer).effective_weight = (*peer).weight;
            (*peer).max_conns = (*template).max_conns;
            (*peer).max_fails = (*template).max_fails;
            (*peer).fail_timeout = (*template).fail_timeout;
            (*peer).down = (*template).down;

            copy_round_robin_sid(peer, template);

            *peerp = peer;
            peerp = &mut (*peer).next;

            (*peers).number += 1;
            (*peers).tries += ((*peer).down == 0) as usize;
            (*peers).total_weight += (*peer).weight as usize;
            (*peers).weighted = (*peers).total_weight != (*peers).number;
            *(*peers).config += 1;

            set_single(uscf);
        }

        if !service.is_empty() && !(*peers).next.is_null() {
            peers_unlock(peers);

            peers = (*peers).next;
            backup = true;

            peers_wlock(peers);

            continue;
        }

        break;
    }

    // done:

    let valid = ctx.valid.get();

    (*host).valid = valid;

    peers_unlock(peers);

    1000 * (if valid > now { valid - now + 1 } else { 1 }) as u64
}

pub fn upstream_zone_module() -> ModuleDef {
    let commands = vec![cmd_fn!("zone", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE12, ConfLevel::None, zone_handler)];
    let mut m = http_module_def("ngx_http_upstream_zone_module", HttpModuleDef::default(), commands);
    m.init_process = Some(init_worker);
    m
}
