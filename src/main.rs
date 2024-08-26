use cyclonedx_bom::{
    models::{component::Classification, dependency::{Dependencies, Dependency}},
    prelude::*,
};
use std::collections::HashMap;

fn main() {
    if std::env::args().count() != 3 {
        eprintln!("Usage: {} <input-bom> <output-bom>", std::env::args().next().unwrap());
        std::process::exit(1);
    }

    let reader = std::fs::File::open(std::env::args().nth(1).unwrap()).unwrap();
    let mut bom = Bom::parse_from_json(reader).unwrap();

    // Group components by the cataloger that found them and the path they were found at
    let mut grouped_components = group_components(&bom);

    // Create dependency relationships between jar files and their dependencies
    // These are the ones that are found by the java-archive-cataloger
    process_jar_dependencies(&mut bom, &mut grouped_components);

    // Merge components that have the same PURL
    merge_duplicate_components(&mut bom, &grouped_components);

    // Find components with `type` == "operating-system" and change the value of their `name` attribute to "redhat" if it is "rhel"
    // This is currently needed since Trivy won't recognize "rhel" as a known operating system
    if let Some(components) = bom.components.as_mut() {
        for component in &mut components.0 {
            if component.component_type == Classification::OperatingSystem && (component.name.as_ref() as &str) == "rhel" {
                component.name = "redhat".into();
            }
        }
    }

    let mut writer = std::fs::File::create(std::env::args().nth(2).unwrap()).unwrap();
    bom.output_as_json_v1_5(&mut writer).unwrap();
}

fn group_components(bom: &Bom) -> HashMap<String, HashMap<String, Vec<Component>>> {
    let mut grouped = HashMap::new();
    if let Some(components) = &bom.components {
        for component in &components.0 {
            if let Some(found_by) = component.get_property("syft:package:foundBy") {
                if let Some(path) = component.get_property("syft:location:0:path") {
                    grouped
                        .entry(found_by)
                        .or_insert_with(HashMap::new)
                        .entry(path)
                        .or_insert_with(Vec::new)
                        .push(component.clone());
                }
            }
        }
    }
    grouped
}

fn process_jar_dependencies(
    bom: &mut Bom,
    grouped_components: &mut HashMap<String, HashMap<String, Vec<Component>>>,
) {
    if let Some(jars) = grouped_components.get("java-archive-cataloger") {
        for (jar_file_path, jar_components) in jars {
            let (parent, children): (Vec<_>, Vec<_>) = jar_components.iter().partition(|c| {
                c.get_property("syft:metadata:virtualPath").as_ref() == Some(jar_file_path)
            });

            if let Some(parent) = parent.first() {
                if !children.is_empty() {
                    let dependency = Dependency {
                        dependency_ref: parent.bom_ref.as_ref().unwrap().to_string(),
                        dependencies: children
                            .iter()
                            .filter_map(|c| c.bom_ref.as_ref().map(|r| r.to_string()))
                            .collect(),
                    };
                    bom.dependencies
                        .get_or_insert_with(|| Dependencies(vec![]))
                        .0
                        .push(dependency);
                }
            }
        }
    }
}

fn merge_duplicate_components(
    bom: &mut Bom,
    grouped_components: &HashMap<String, HashMap<String, Vec<Component>>>,
) {
    if let Some(sboms) = grouped_components.get("sbom-cataloger") {
        let mut purl_map = HashMap::new();
        for sbom_component in sboms.values().flatten() {
            if let Some(purl) = &sbom_component.purl {
                let key = purl.as_ref().split('?').next().unwrap();
                purl_map.insert(key, sbom_component);
            }
        }

        if let Some(components) = bom.components.as_mut() {
            let mut merged_non_sbom_components = HashMap::<String, String>::new();
            components.0.retain(|component| {
                if let Some(component_purl) = &component.purl {
                    let component_purl = component_purl.as_ref().split('?').next().unwrap();

                    let component_bom_ref = component.bom_ref.as_ref().unwrap();

                    if let Some(sbom_component) = purl_map.get(component_purl) {
                        let sbom_component_bom_ref = sbom_component.bom_ref.as_ref().unwrap();
                        update_dependencies(
                            bom.dependencies.as_mut(),
                            component_bom_ref,
                            sbom_component_bom_ref,
                        );
                        // only retain if it is the SBOM component
                        return component_bom_ref == sbom_component_bom_ref;
                    } else {
                        // no SBOM component found for this PURL, still merge all other components
                        if let Some(first_component_bom_ref) =
                            merged_non_sbom_components.get(component_purl)
                        {
                            update_dependencies(
                                bom.dependencies.as_mut(),
                                component_bom_ref,
                                first_component_bom_ref,
                            );
                            return false;
                        } else {
                            merged_non_sbom_components
                                .insert(component_purl.to_string(), component_bom_ref.clone());
                        }
                    }
                }
                true
            });
        }
    }
}

fn update_dependencies(
    dependencies: Option<&mut Dependencies>,
    old_component_bom_ref: &String,
    new_component_bom_ref: &str,
) {
    if let Some(dependencies) = dependencies {
        for dependency in &mut dependencies.0 {
            if &dependency.dependency_ref == old_component_bom_ref {
                dependency.dependency_ref = new_component_bom_ref.to_owned();
            }
            for dep in &mut dependency.dependencies {
                if dep == old_component_bom_ref {
                    *dep = new_component_bom_ref.to_owned();
                }
            }
        }
    }
}

trait ComponentExt {
    fn get_property(&self, name: &str) -> Option<String>;
}

impl ComponentExt for Component {
    fn get_property(&self, name: &str) -> Option<String> {
        self.properties.as_ref().and_then(|props| {
            props
                .0
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.value.to_string())
        })
    }
}
