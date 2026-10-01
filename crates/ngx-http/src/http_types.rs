//! The MIME types lists of the filters (gzip_types, sub_filter_types, ...):
//! ngx_http_types_slot(), ngx_http_merge_types() and
//! ngx_http_set_default_types() of ngx_http.c.

use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::hash::{hash_key, hash_strlow, Hash, HashInit, HashKey};
use ngx_core::log::*;
use ngx_core::ngx_log_error;
use ngx_core::string::B;

use crate::request::R;

/// ngx_http_html_default_types
pub const NGX_HTTP_HTML_DEFAULT_TYPES: &[&[u8]] = &[b"text/html"];

/// The keys a types directive collects (the ngx_array_t of
/// ngx_http_types_slot()): `*` is (void *) -1
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpTypesKeys {
    Any,
    List(Vec<Vec<u8>>),
}

/// The types hash of a configuration: None while ngx_hash_init() has not
/// built it (buckets == NULL), which ngx_http_test_content_type() takes as
/// an empty hash, matching any type.
pub type HttpTypesHash = Option<Rc<Hash<Rc<Vec<u8>>>>>;

/// ngx_http_types_slot, `default_type` being cmd->post
pub fn http_types_slot(cf: &Conf, types: &mut Option<HttpTypesKeys>, default_type: Option<&[u8]>) -> ConfResult {
    if *types == Some(HttpTypesKeys::Any) {
        return Ok(());
    }

    if types.is_none() {
        let mut list = Vec::new();

        if let Some(t) = default_type {
            list.push(t.to_vec());
        }

        *types = Some(HttpTypesKeys::List(list));
    }

    for value in cf.args[1..].iter() {
        if value.as_slice() == b"*" {
            *types = Some(HttpTypesKeys::Any);
            return Ok(());
        }

        let mut lowcase = vec![0u8; value.len()];
        hash_strlow(&mut lowcase, value);

        if let Some(HttpTypesKeys::List(list)) = types {
            if list.iter().any(|t| *t == lowcase) {
                cf.warn(format_args!("duplicate MIME type \"{}\"", B(&lowcase)));
                continue;
            }

            list.push(lowcase);
        }
    }

    Ok(())
}

/// ngx_http_merge_types
pub fn http_merge_types(
    cf: &Conf,
    keys: &mut Option<HttpTypesKeys>,
    types_hash: &mut HttpTypesHash,
    prev_keys: &mut Option<HttpTypesKeys>,
    prev_types_hash: &mut HttpTypesHash,
    default_types: &[&[u8]],
) -> ConfResult {
    if let Some(k) = keys {
        if let HttpTypesKeys::List(list) = k {
            *types_hash = Some(Rc::new(types_hash_init(cf, list)?));
        }

        return Ok(());
    }

    if prev_types_hash.is_none() {
        match prev_keys {
            None => {
                // ngx_http_set_default_types
                *prev_keys = Some(HttpTypesKeys::List(default_types.iter().map(|t| t.to_vec()).collect()));
            }
            Some(HttpTypesKeys::Any) => {
                *keys = prev_keys.clone();
                return Ok(());
            }
            Some(HttpTypesKeys::List(_)) => {}
        }

        if let Some(HttpTypesKeys::List(list)) = prev_keys {
            *prev_types_hash = Some(Rc::new(types_hash_init(cf, list)?));
        }
    }

    *types_hash = prev_types_hash.clone();

    Ok(())
}

/// ngx_hash_init() of a "test_types_hash"
fn types_hash_init(cf: &Conf, list: &[Vec<u8>]) -> Result<Hash<Rc<Vec<u8>>>, ConfError> {
    let names = list.iter().map(|t| HashKey { key: t.clone(), key_hash: hash_key(t), value: Rc::new(t.clone()) }).collect();

    let hash = HashInit { name: "test_types_hash", max_size: 2048, bucket_size: 64, log: &cf.log };

    Hash::init(&hash, names).map_err(|e| {
        ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
        ConfError::Logged
    })
}

/// ngx_http_test_content_type() != NULL: a hash not built (an empty one)
/// matches any type
pub fn http_test_content_type(r: &R, types_hash: &HttpTypesHash) -> bool {
    match types_hash {
        None => true,
        Some(hash) => crate::core_rt::test_content_type(r, hash).is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_keys_are_kept() {
        let keys = Some(HttpTypesKeys::Any);
        assert_eq!(keys, Some(HttpTypesKeys::Any));
        assert_ne!(keys, Some(HttpTypesKeys::List(vec![b"text/html".to_vec()])));
    }
}
