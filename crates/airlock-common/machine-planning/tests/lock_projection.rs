//! Lock pruning may remove nodes but must preserve every retained name, edge and root binding.

use airlock_machine_planning::lock_projection::matches;

/// Node removal and order changes are safe; substitution and rewiring are not.
#[test]
fn pruning_preserves_complete_node_bindings() {
    let original = ["node-a: source-a -> node-b", "node-b: source-b"];
    assert!(matches("root:a,b", "root:a,b", &original, &original));
    assert!(matches("root:b", "root:b", &original, &original[1..]));
    assert!(matches(
        "root:b,a",
        "root:b,a",
        &original,
        &[original[1], original[0]]
    ));
    assert!(!matches("root:b", "root:a", &original, &original));
    assert!(!matches(
        "root:a,b",
        "root:a,b",
        &original,
        &["node-a: source-a -> other-node"]
    ));
    assert!(!matches(
        "root:a,b",
        "root:a,b",
        &original,
        &["node-b: substituted-source"]
    ));
}
