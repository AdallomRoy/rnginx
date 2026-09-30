//! ngx_json.c: the JSON text of a data item.

use std::io::Write;

use crate::data::DataItem;
use crate::string::escape_json_into;

/// ngx_json_render
pub fn render(item: &DataItem) -> Vec<u8> {
    let mut p = Vec::with_capacity(256);

    encode(&mut p, item);

    p
}

/// the ngx_json_*_encode functions
fn encode(p: &mut Vec<u8>, item: &DataItem) {
    match item {
        DataItem::Object(items) => {
            p.push(b'{');

            for (n, (name, i)) in items.iter().enumerate() {
                if n > 0 {
                    p.push(b',');
                }

                p.push(b'"');
                escape_json_into(p, name);
                p.push(b'"');
                p.push(b':');

                encode(p, i);
            }

            p.push(b'}');
        }

        DataItem::List(items) => {
            p.push(b'[');

            for (n, i) in items.iter().enumerate() {
                if n > 0 {
                    p.push(b',');
                }

                encode(p, i);
            }

            p.push(b']');
        }

        DataItem::String(s) => {
            p.push(b'"');
            escape_json_into(p, s);
            p.push(b'"');
        }

        DataItem::Integer(n) => {
            let _ = write!(p, "{}", n);
        }

        DataItem::Boolean(b) => p.extend_from_slice(if *b { b"true" } else { b"false" }),

        DataItem::Null => p.extend_from_slice(b"null"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render() {
        let mut obj = DataItem::new_object();

        let mut list = DataItem::new_list();
        list.add_item(None, DataItem::string(b"a\"b\\c\n\x01"));
        list.add_item(None, DataItem::Integer(-42));
        list.add_item(None, DataItem::Boolean(true));
        list.add_item(None, DataItem::Boolean(false));
        list.add_item(None, DataItem::Null);

        obj.add_item(Some(b"list"), list);
        obj.add_item(Some(b"k\"ey"), DataItem::new_object());
        obj.add_item(Some(b"empty"), DataItem::new_list());

        assert_eq!(render(&obj), br#"{"list":["a\"b\\c\n\u0001",-42,true,false,null],"k\"ey":{},"empty":[]}"#.to_vec());
    }
}
