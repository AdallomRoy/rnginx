use ngx_core::module::ModuleDef;

pub mod parse;

pub fn modules() -> Vec<ModuleDef> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modules() {
        let m = modules();
        assert_eq!(m.len(), 0);
    }
}
