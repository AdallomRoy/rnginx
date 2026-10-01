//! ngx_data.c: the data items of an API response (objects, lists, strings,
//! integers, booleans and null), rendered by crate::json.

/// ngx_data_item_t
#[derive(Clone, Debug, PartialEq)]
pub enum DataItem {
    /// the items with their names, in the order they were added
    Object(Vec<(Vec<u8>, DataItem)>),
    List(Vec<DataItem>),
    String(Vec<u8>),
    Integer(i64),
    Boolean(bool),
    Null,
}

impl DataItem {
    /// ngx_data_new_object
    pub fn new_object() -> DataItem {
        DataItem::Object(Vec::new())
    }

    /// ngx_data_new_list
    pub fn new_list() -> DataItem {
        DataItem::List(Vec::new())
    }

    /// ngx_data_add_item: an item appended to an object (with its name) or
    /// to a list; other items take none
    pub fn add_item(&mut self, name: Option<&[u8]>, item: DataItem) {
        match self {
            DataItem::Object(items) => items.push((name.unwrap_or_default().to_vec(), item)),
            DataItem::List(items) => items.push(item),
            _ => {}
        }
    }

    /// ngx_data_string_handler
    pub fn string(s: &[u8]) -> DataItem {
        DataItem::String(s.to_vec())
    }

    /// ngx_data_time_handler: the time in ISO 8601, with the milliseconds if
    /// there are any
    pub fn time(sec: i64, msec: u64) -> DataItem {
        let tm = crate::times::gmtime(sec);

        let mut s = format!("{:4}-{:02}-{:02}T{:02}:{:02}:{:02}", tm.year, tm.mon, tm.mday, tm.hour, tm.min, tm.sec);

        if msec != 0 {
            s.push_str(&format!(".{:03}", msec));
        }

        s.push('Z');

        DataItem::String(s.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_item() {
        let mut obj = DataItem::new_object();
        obj.add_item(Some(b"a"), DataItem::Integer(1));
        obj.add_item(None, DataItem::Null);

        assert_eq!(obj, DataItem::Object(vec![(b"a".to_vec(), DataItem::Integer(1)), (Vec::new(), DataItem::Null)]));

        let mut list = DataItem::new_list();
        list.add_item(Some(b"ignored"), DataItem::Boolean(true));

        assert_eq!(list, DataItem::List(vec![DataItem::Boolean(true)]));

        let mut s = DataItem::string(b"x");
        s.add_item(None, DataItem::Null);

        assert_eq!(s, DataItem::String(b"x".to_vec()));
    }

    #[test]
    fn test_time() {
        assert_eq!(DataItem::time(0, 0), DataItem::String(b"1970-01-01T00:00:00Z".to_vec()));
        assert_eq!(DataItem::time(1790769600, 5), DataItem::String(b"2026-09-30T12:00:00.005Z".to_vec()));
    }
}
