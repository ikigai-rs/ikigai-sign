use oxrdf::Term;
use oxrdfio::{RdfFormat, RdfParser};

#[test]
fn ontology_version_is_the_crate_version() {
    let quads = RdfParser::from_format(RdfFormat::Turtle)
        .for_slice(ikigai_sign::VOCABULARY_TTL.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("the vocabulary must parse as Turtle");
    assert!(
        quads.iter().any(|quad| {
            quad.subject.to_string() == "<https://ikigai-rs.dev/ns/sign>"
                && quad.predicate.as_str() == "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
                && quad.object
                    == Term::NamedNode(
                        oxrdf::NamedNode::new("http://www.w3.org/2002/07/owl#Ontology").unwrap(),
                    )
        }),
        "the document declares its ontology"
    );
    let version_lines: Vec<_> = ikigai_sign::VOCABULARY_TTL
        .lines()
        .filter(|line| line.trim_start().starts_with("owl:versionInfo"))
        .collect();
    assert_eq!(
        version_lines,
        [format!(
            "    owl:versionInfo \"{}\" .",
            env!("CARGO_PKG_VERSION")
        )],
        "the release preflight and drift scan read this line"
    );
    let versions: Vec<_> = quads
        .iter()
        .filter(|quad| {
            quad.subject.to_string() == "<https://ikigai-rs.dev/ns/sign>"
                && quad.predicate.as_str() == "http://www.w3.org/2002/07/owl#versionInfo"
        })
        .map(|quad| &quad.object)
        .collect();
    assert_eq!(
        versions,
        [&Term::Literal(oxrdf::Literal::new_simple_literal(env!(
            "CARGO_PKG_VERSION"
        )))]
    );
}

#[test]
fn every_sig_term_is_defined_without_domains() {
    use ikigai_sign::{
        SIG_ALGORITHM, SIG_CONTENT_HASH, SIG_NS, SIG_SIGNATURE, SIG_SIGNER, SIG_VALUE,
    };
    let quads = RdfParser::from_format(RdfFormat::Turtle)
        .for_slice(ikigai_sign::VOCABULARY_TTL.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("the vocabulary must parse as Turtle");
    let terms = [
        SIG_SIGNATURE,
        SIG_ALGORITHM,
        SIG_SIGNER,
        SIG_VALUE,
        SIG_CONTENT_HASH,
    ];
    for term in terms {
        let subject = oxrdf::NamedOrBlankNode::from(oxrdf::NamedNode::new(term).unwrap());
        for predicate in [
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
            "http://www.w3.org/2000/01/rdf-schema#label",
            "http://www.w3.org/2000/01/rdf-schema#comment",
        ] {
            assert_eq!(
                quads
                    .iter()
                    .filter(|q| q.subject == subject && q.predicate.as_str() == predicate)
                    .count(),
                1,
                "{term} must have one {predicate}"
            );
        }
    }
    assert!(terms.iter().all(|term| term.starts_with(SIG_NS)));
    assert!(
        quads
            .iter()
            .all(|q| q.predicate.as_str() != "http://www.w3.org/2000/01/rdf-schema#domain"),
        "a domain would type log and ledger subjects as signatures"
    );

    // Read the declarations too, so a newly added SIG_* IRI cannot silently escape
    // the list above. SIG_NS is a namespace and SIG_FIELDS is an internal lookup.
    for line in include_str!("../src/lib.rs")
        .lines()
        .filter(|line| line.starts_with("pub const SIG_") || line.starts_with("const SIG_"))
    {
        if let Some((_, rest)) = line.split_once("&str = \"") {
            let iri = rest.split('"').next().unwrap();
            assert!(
                iri == SIG_NS || terms.contains(&iri),
                "new term needs vocabulary coverage: {line}"
            );
        }
    }
}
