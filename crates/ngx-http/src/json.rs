//! ngx_http_json_module: "json_set $var $source path" makes $var the value
//! at the path of the JSON document in $source. The paths of all the
//! variables of a source are a tree walked while the document is parsed
//! once (crate ngx_core::json_parse): the values found are kept for the
//! request, the objects and arrays as their text.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::json_parse::{JsonCtx, JsonEvent, NGX_JSON_SKIP};
use ngx_core::json_unescape::unescape_string;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::{atoi, B};
use ngx_core::cmd_fn;

use crate::request::*;
use crate::variables::{add_variable, get_flushed_variable, get_variable_index, GetHandler, NGX_HTTP_VAR_CHANGEABLE};
use crate::*;

crate::http_module_index!("ngx_http_json_module");

const NGX_HTTP_JSON_DEFAULT_MAX_DEPTH: i64 = 32;

/// ngx_http_json_seg_t: a key, or an index of an array
#[derive(Clone, Debug)]
struct Seg {
    is_index: bool,
    key: Vec<u8>,
    index: usize,
}

impl Seg {
    fn key(key: &[u8]) -> Seg {
        Seg { is_index: false, key: key.to_vec(), index: 0 }
    }

    fn index(index: usize) -> Seg {
        Seg { is_index: true, key: Vec::new(), index }
    }
}

/// ngx_http_json_node_t: a node of the tree of the paths of a source, with
/// the variables its value goes to
#[derive(Debug)]
struct Node {
    seg: Seg,
    children: Vec<Node>,
    dests: Vec<usize>,
}

impl Node {
    fn new(seg: Seg) -> Node {
        Node { seg, children: Vec::new(), dests: Vec::new() }
    }
}

/// ngx_http_json_source_t
struct Source {
    /// the index of the source variable
    index: usize,
    root: Node,
}

/// ngx_http_json_main_conf_t
pub struct JsonMainConf {
    max_depth: Val<i64>,
    sources: Vec<Source>,
    /// ngx_http_json_variable_t: the source of each variable
    variables: Vec<usize>,
}

/// The values of the variables of a request (the module's context).
struct JsonValues(Vec<VariableValue>);

// ---------------------------------------------------------------------------
// the variables
// ---------------------------------------------------------------------------

/// ngx_http_json_variable
fn json_variable(r: &R, v: &mut VariableValue, data: usize) -> i64 {
    let oi = data;

    let jmcf_rc = r.main_conf::<JsonMainConf>(ctx_index());
    let jmcf = jmcf_rc.borrow();

    if jmcf.variables.is_empty() || oi >= jmcf.variables.len() {
        v.not_found = true;
        return NGX_OK;
    }

    let values = match r.get_ctx::<JsonValues>(ctx_index()) {
        Some(c) => c,
        None => r.set_ctx(ctx_index(), JsonValues(vec![VariableValue::default(); jmcf.variables.len()])),
    };

    {
        let vals = values.borrow();
        let cached = &vals.0[oi];

        if cached.valid || cached.not_found {
            *v = cached.clone();
            return NGX_OK;
        }
    }

    let si = jmcf.variables[oi];
    let src = &jmcf.sources[si];

    // the source may be a variable of the module too: no borrow of the
    // values is held while it is evaluated

    let vv = match get_flushed_variable(r, src.index) {
        Some(vv) => vv,
        None => return NGX_ERROR,
    };

    let mut vals = values.borrow_mut();

    reset(&mut vals.0, &jmcf, si);

    if vv.not_found || vv.data.is_empty() {
        *v = vals.0[oi].clone();
        return NGX_OK;
    }

    let rc = {
        let mut state = State { values: &mut vals.0, stack: Vec::with_capacity(8), current_key: None, current_node: None, root: &src.root };

        let mut jctx = JsonCtx::new();

        jctx.max_depth = *jmcf.max_depth as usize;

        let doc = &vv.data[..];

        jctx.parse(doc, &mut |event, start, len| json_handler(&mut state, doc, event, start, len))
    };

    if rc == NGX_OK {
        *v = vals.0[oi].clone();
        return NGX_OK;
    }

    reset(&mut vals.0, &jmcf, si);

    if rc == NGX_DECLINED {
        http_debug!(r, "json_set: invalid JSON source");
    }

    if rc == NGX_ERROR {
        return NGX_ERROR;
    }

    *v = vals.0[oi].clone();

    NGX_OK
}

/// ngx_http_json_reset: the variables of a source not found
fn reset(values: &mut [VariableValue], jmcf: &JsonMainConf, source_index: usize) {
    for (i, &si) in jmcf.variables.iter().enumerate() {
        if si != source_index {
            continue;
        }

        values[i].valid = false;
        values[i].not_found = true;
    }
}

/// ngx_http_json_frame_t: an object or array of the document being parsed
struct Frame<'n> {
    index: usize,
    /// the offset of its "{" or "["
    start: usize,
    node: &'n Node,
    is_array: bool,
}

/// ngx_http_json_state_t
struct State<'n, 'v> {
    values: &'v mut Vec<VariableValue>,
    stack: Vec<Frame<'n>>,
    /// the key of the member whose value comes next (its data being set in
    /// C, an empty key included)
    current_key: Option<Vec<u8>>,
    current_node: Option<&'n Node>,
    root: &'n Node,
}

/// ngx_http_json_handler
fn json_handler<'n>(state: &mut State<'n, '_>, data: &[u8], event: JsonEvent, start: usize, len: usize) -> i64 {
    let token = &data[start..start + len];

    match event {
        JsonEvent::ObjectOpen | JsonEvent::ArrayOpen => {
            if state.stack.is_empty() {
                state.current_key = None;
                state.current_node = None;

                let root = state.root;

                push(state, event, start, root);

                return NGX_OK;
            }

            let is_member = state.current_key.is_some();
            state.current_key = None;

            let node = if is_member {
                state.current_node.take()
            } else {
                let node = {
                    let top = state.stack.last().expect("frame");
                    lookup_index(top.node, top.index)
                };

                inc_index(state);

                node
            };

            let node = match node {
                Some(n) => n,
                None => return NGX_JSON_SKIP,
            };

            push(state, event, start, node);
        }

        JsonEvent::ObjectClose | JsonEvent::ArrayClose => {
            if let Some(top) = state.stack.pop() {
                if !top.node.dests.is_empty() {
                    let slice = &data[top.start..start + 1];

                    if store(state.values, top.node, slice, false) != NGX_OK {
                        return NGX_ERROR;
                    }
                }
            }
        }

        JsonEvent::Key => {
            let key = if token.contains(&b'\\') {
                let mut k = token.to_vec();

                if unescape_string(&mut k).is_err() {
                    return NGX_ERROR;
                }

                k
            } else {
                token.to_vec()
            };

            let node = match state.stack.last() {
                Some(top) => lookup_key(top.node, &key),
                None => None,
            };

            match node {
                None => {
                    state.current_key = None;
                    state.current_node = None;
                    return NGX_JSON_SKIP;
                }

                Some(n) => {
                    state.current_key = Some(key);
                    state.current_node = Some(n);
                }
            }
        }

        JsonEvent::ValueString | JsonEvent::ValueNumber | JsonEvent::ValueBool | JsonEvent::ValueNull => {
            if state.stack.is_empty() {
                state.current_key = None;
                state.current_node = None;
                return NGX_OK;
            }

            let is_member = state.current_key.is_some();
            state.current_key = None;

            let node = if is_member {
                state.current_node.take()
            } else {
                let node = {
                    let top = state.stack.last().expect("frame");
                    lookup_index(top.node, top.index)
                };

                inc_index(state);

                node
            };

            if let Some(node) = node {
                if !node.dests.is_empty() && store(state.values, node, token, event == JsonEvent::ValueString) != NGX_OK {
                    return NGX_ERROR;
                }
            }
        }
    }

    NGX_OK
}

/// ngx_http_json_inc_index
fn inc_index(state: &mut State<'_, '_>) {
    if let Some(top) = state.stack.last_mut() {
        if top.is_array {
            top.index += 1;
        }
    }
}

/// ngx_http_json_lookup_key
fn lookup_key<'n>(parent: &'n Node, key: &[u8]) -> Option<&'n Node> {
    parent.children.iter().find(|c| !c.seg.is_index && c.seg.key == key)
}

/// ngx_http_json_lookup_index
fn lookup_index(parent: &Node, index: usize) -> Option<&Node> {
    parent.children.iter().find(|c| c.seg.is_index && c.seg.index == index)
}

/// ngx_http_json_store: the value of the node for its variables
fn store(values: &mut [VariableValue], node: &Node, value: &[u8], unescape: bool) -> i64 {
    let mut val = value.to_vec();

    if !val.is_empty() && unescape && unescape_string(&mut val).is_err() {
        return NGX_ERROR;
    }

    for &d in node.dests.iter() {
        let slot = &mut values[d];

        slot.valid = true;
        slot.not_found = false;
        slot.no_cacheable = false;
        slot.escape = false;
        slot.data = val.clone();
    }

    NGX_OK
}

/// ngx_http_json_push
fn push<'n>(state: &mut State<'n, '_>, event: JsonEvent, start: usize, node: &'n Node) {
    state.stack.push(Frame { index: 0, start, is_array: event == JsonEvent::ArrayOpen, node });
}

// ---------------------------------------------------------------------------
// the configuration
// ---------------------------------------------------------------------------

/// ngx_http_json_set
fn json_set(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let jmcf_rc = conf_rc::<JsonMainConf>(conf.as_ref().expect("conf"));

    let value = cf.args.clone();

    let name = &value[1];

    if name.first() != Some(&b'$') {
        return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(name))));
    }

    let name = &name[1..];

    let var = add_variable(cf, name, NGX_HTTP_VAR_CHANGEABLE)?;

    if var.get_handler.get().is_some_and(|h| std::ptr::fn_addr_eq(h, json_variable as GetHandler)) {
        return Err(cf.emerg(format_args!("json_set variable \"{}\" is already defined", B(name))));
    }

    let source = &value[2];

    if source.first() != Some(&b'$') {
        return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(source))));
    }

    let sindex = get_variable_index(cf, &source[1..])?;

    let mut jmcf = jmcf_rc.borrow_mut();

    let si = match jmcf.sources.iter().position(|s| s.index == sindex) {
        Some(i) => i,
        None => {
            jmcf.sources.push(Source { index: sindex, root: Node::new(Seg::key(b"")) });
            jmcf.sources.len() - 1
        }
    };

    let oi = jmcf.variables.len();

    jmcf.variables.push(si);

    insert_path(cf, &mut jmcf.sources[si].root, oi, &value[3])?;

    var.get_handler.set(Some(json_variable));
    var.data.set(oi);

    Ok(())
}

/// ngx_http_json_insert_path: the nodes of a path ("a.b[0]", "a["k.y"]"),
/// the last with the variable
fn insert_path(cf: &Conf, root: &mut Node, dest: usize, path: &[u8]) -> ConfResult {
    const SW_START: u8 = 0;
    const SW_KEY: u8 = 1;
    const SW_DOT: u8 = 2;
    const SW_BRACKET: u8 = 3;
    const SW_INDEX: u8 = 4;
    const SW_QUOTED: u8 = 5;
    const SW_QUOTED_ESCAPE: u8 = 6;
    const SW_QUOTED_CLOSE: u8 = 7;
    const SW_AFTER_BRACKET: u8 = 8;

    if path.is_empty() {
        return Err(cf.emerg(format_args!("empty json_set path")));
    }

    let invalid = |cf: &Conf| Err(cf.emerg(format_args!("invalid json_set path \"{}\"", B(path))));

    let mut node: &mut Node = root;
    let mut start = 0;

    let mut state = SW_START;

    for (p, &ch) in path.iter().enumerate() {
        match state {
            SW_START => {
                if ch == b'[' {
                    state = SW_BRACKET;
                    continue;
                }

                if ch == b'.' || ch == b'$' {
                    return invalid(cf);
                }

                start = p;
                state = SW_KEY;
            }

            SW_KEY => {
                if ch == b'.' || ch == b'[' {
                    node = child(node, Seg::key(&path[start..p]));

                    state = if ch == b'.' { SW_DOT } else { SW_BRACKET };
                }
            }

            SW_DOT => {
                if ch == b'.' || ch == b'[' || ch == b'$' {
                    return invalid(cf);
                }

                start = p;
                state = SW_KEY;
            }

            SW_BRACKET => {
                if ch == b'"' {
                    start = p + 1;
                    state = SW_QUOTED;
                    continue;
                }

                if ch.is_ascii_digit() {
                    start = p;
                    state = SW_INDEX;
                    continue;
                }

                return invalid(cf);
            }

            SW_INDEX => {
                if ch.is_ascii_digit() {
                    continue;
                }

                if ch != b']' {
                    return invalid(cf);
                }

                let index = match atoi(&path[start..p]) {
                    Some(i) => i as usize,
                    None => return invalid(cf),
                };

                node = child(node, Seg::index(index));

                state = SW_AFTER_BRACKET;
            }

            SW_QUOTED => {
                if ch == b'\\' {
                    state = SW_QUOTED_ESCAPE;
                    continue;
                }

                if ch == b'"' {
                    let mut key = path[start..p].to_vec();

                    if unescape_string(&mut key).is_err() {
                        return invalid(cf);
                    }

                    node = child(node, Seg { is_index: false, key, index: 0 });

                    state = SW_QUOTED_CLOSE;
                }
            }

            SW_QUOTED_ESCAPE => state = SW_QUOTED,

            SW_QUOTED_CLOSE => {
                if ch != b']' {
                    return invalid(cf);
                }

                state = SW_AFTER_BRACKET;
            }

            _ => {
                // SW_AFTER_BRACKET

                if ch == b'.' {
                    state = SW_DOT;
                    continue;
                }

                if ch == b'[' {
                    state = SW_BRACKET;
                    continue;
                }

                return invalid(cf);
            }
        }
    }

    match state {
        SW_KEY => node = child(node, Seg::key(&path[start..])),
        SW_AFTER_BRACKET => {}
        _ => return invalid(cf),
    }

    node.dests.push(dest);

    Ok(())
}

/// ngx_http_json_child: the child of a node for a segment, added if there is
/// none yet
fn child(parent: &mut Node, seg: Seg) -> &mut Node {
    let found = parent.children.iter().position(|c| if seg.is_index { c.seg.is_index && c.seg.index == seg.index } else { !c.seg.is_index && c.seg.key == seg.key });

    let i = match found {
        Some(i) => i,
        None => {
            parent.children.push(Node::new(seg));
            parent.children.len() - 1
        }
    };

    &mut parent.children[i]
}

/// ngx_http_json_create_main_conf
fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    Rc::new(RefCell::new(JsonMainConf { max_depth: Val::unset(), sources: Vec::new(), variables: Vec::new() }))
}

/// ngx_http_json_init_main_conf
fn init_main_conf(_cf: &mut Conf, conf: &Rc<dyn Any>) -> ConfResult {
    let mut jmcf = conf_cell::<JsonMainConf>(conf).borrow_mut();

    jmcf.max_depth.init(NGX_HTTP_JSON_DEFAULT_MAX_DEPTH);

    Ok(())
}

/// json_max_depth: ngx_conf_set_num_slot with ngx_http_json_max_depth_bounds
fn json_max_depth(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<JsonMainConf>(conf.as_ref().expect("conf"));
    let mut c = cell.borrow_mut();

    set_num(cf, cmd, &mut c.max_depth)?;

    check_num_bounds(cf, *c.max_depth, 1, 256)
}

pub fn json_module() -> ModuleDef {
    let commands = vec![
        cmd_fn!("json_set", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE3, ConfLevel::Main, json_set),
        cmd_fn!("json_max_depth", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, json_max_depth),
    ];

    let def = HttpModuleDef { create_main_conf: Some(create_main_conf), init_main_conf: Some(init_main_conf), ..Default::default() };

    http_module_def("ngx_http_json_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// a configuration context logging nothing
    fn with_conf<T>(f: impl FnOnce(&Conf) -> T) -> T {
        let log = ngx_core::log::Log::stderr(0);
        let mut cycle = ngx_core::cycle::Cycle::init_cycle(log.clone(), Rc::new(Vec::new()));
        let cf = Conf::new(&mut cycle, log);

        f(&cf)
    }

    /// the values of a document for the paths
    fn values(paths: &[&str], doc: &[u8], max_depth: usize) -> (i64, Vec<Option<String>>) {
        let mut root = Node::new(Seg::key(b""));

        with_conf(|cf| {
            for (i, p) in paths.iter().enumerate() {
                insert_path(cf, &mut root, i, p.as_bytes()).expect("path");
            }
        });

        let mut vals = vec![VariableValue::default(); paths.len()];

        for v in vals.iter_mut() {
            v.not_found = true;
        }

        let rc = {
            let mut state = State { values: &mut vals, stack: Vec::new(), current_key: None, current_node: None, root: &root };
            let mut jctx = JsonCtx::new();
            jctx.max_depth = max_depth;
            jctx.parse(doc, &mut |event, start, len| json_handler(&mut state, doc, event, start, len))
        };

        (rc, vals.iter().map(|v| if v.valid { Some(String::from_utf8_lossy(&v.data).into_owned()) } else { None }).collect())
    }

    fn some(s: &str) -> Option<String> {
        Some(s.to_string())
    }

    #[test]
    fn test_values() {
        let (rc, v) = values(
            &["name", "tags[1]", "tags", "a.b", "a.b.c", "m[1][0]", "e", "[\"k.y\"].z", "none"],
            br#"{"name":"J\u00f6","tags":[1,{"x":[2]}],"a":{"b":{"c":7,"d":8}},"m":[[1],[3,4]],"e":"a\nb","k.y":{"z":null}}"#,
            32,
        );

        assert_eq!(rc, NGX_OK);
        assert_eq!(v, vec![some("J\u{f6}"), some(r#"{"x":[2]}"#), some(r#"[1,{"x":[2]}]"#), some(r#"{"c":7,"d":8}"#), some("7"), some("3"), some("a\nb"), some("null"), None]);
    }

    #[test]
    fn test_values_duplicates_and_top_array() {
        let (rc, v) = values(&["dup", "[1]"], br#"{"dup":"first","dup":"second"}"#, 32);
        assert_eq!((rc, v), (NGX_OK, vec![some("second"), None]));

        let (rc, v) = values(&["[1].w", "[0]"], br#"[{"i":{"d":[1,2]}},{"w":"yes"}]"#, 32);
        assert_eq!((rc, v), (NGX_OK, vec![some("yes"), some(r#"{"i":{"d":[1,2]}}"#)]));
    }

    #[test]
    fn test_values_invalid_and_depth() {
        assert_eq!(values(&["a.b"], br#"{"a":{"b":1}"#, 32).0, NGX_DECLINED);
        assert_eq!(values(&["a"], br#"{"a":{"b":{"c":1}}}"#, 2).0, NGX_DECLINED);
    }

    #[test]
    fn test_insert_path_invalid() {
        with_conf(|cf| insert_paths(cf));
    }

    fn insert_paths(cf: &Conf) {
        for p in [".foo", "a[0]b", "a[\"x\"]y", "foo.", "foo..bar", "$.foo", "$", "a[]", "a[xyz]", "a[1a]", "a[12", "a[99999999999999999999]", "a[\"abc", "a[\"x\"", "a[\"x\"b", "a[\"\\q\"]", "a[\"\\u12\"]", "a[\"\\uDC00\"]", ""] {
            let mut root = Node::new(Seg::key(b""));

            assert!(insert_path(cf, &mut root, 0, p.as_bytes()).is_err(), "{}", p);
        }

        let mut root = Node::new(Seg::key(b""));

        assert!(insert_path(cf, &mut root, 0, b"foo[\"x\"].bar").is_ok());
        assert!(insert_path(cf, &mut root, 1, b"foo[\"x\"]").is_ok());

        // the shared prefix is one node

        assert_eq!(root.children.len(), 1);
        assert_eq!(root.children[0].children.len(), 1);
        assert_eq!(root.children[0].children[0].dests, vec![1]);
    }
}
