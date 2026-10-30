use serde::Deserialize;
use tenuo::{Constraint, ConstraintValue, Exact, Subpath, Subset};

#[derive(Deserialize)]
struct Case {
    name: String,
    root: String,
    value: ConstraintValue,
    allowed: bool,
    kind: Option<String>,
}

#[derive(Deserialize)]
struct Suite {
    matching: Vec<Case>,
    attenuation: Vec<Case>,
}

#[test]
fn subpath_list_shared_vectors() {
    let suite: Suite =
        serde_json::from_str(include_str!("../../tests/vectors/subpath-lists.json")).unwrap();
    for case in suite.matching {
        let parent = Subpath::new(&case.root).unwrap();
        assert_eq!(
            parent.matches(&case.value).unwrap(),
            case.allowed,
            "{}",
            case.name
        );
    }
    for case in suite.attenuation {
        let parent = Constraint::Subpath(Subpath::new(&case.root).unwrap());
        let child = match case.kind.as_deref() {
            Some("subset") => {
                Constraint::Subset(Subset::new(case.value.as_list().unwrap().clone()))
            }
            Some("exact") => Constraint::Exact(Exact::new(case.value)),
            _ => panic!("unknown vector kind"),
        };
        assert_eq!(
            parent.validate_attenuation(&child).is_ok(),
            case.allowed,
            "{}",
            case.name
        );
    }
}
