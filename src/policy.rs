//! ABAC policy engine — pure functions, fully unit-tested.
//!
//! Attributes (not bare roles) decide: subject (role, department),
//! action, resource (kind, owner department). Deny by default.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Read,
    Write,
    Approve,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceKind {
    PatientRecord,
    AuditLog,
    SystemConfig,
}

#[derive(Debug, Clone)]
pub struct Resource {
    pub kind: ResourceKind,
    /// Owning department of the record.
    pub department: String,
}

#[derive(Debug, Clone)]
pub struct Subject {
    pub user: String,
    pub role: String,
    pub department: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// The policy: evaluated as ordered rules; first match wins; default deny.
/// Documented like a policy file because that is what it is.
fn rules(subject: &Subject, action: &Action, resource: &Resource) -> Decision {
    // R1: nobody reads the audit log except auditors.
    if matches!(resource.kind, ResourceKind::AuditLog) {
        return if subject.role == "auditor" && matches!(action, Action::Read) {
            Decision::Allow
        } else {
            Decision::Deny
        };
    }

    // R2: system config is admin-only.
    if matches!(resource.kind, ResourceKind::SystemConfig) {
        return if subject.role == "admin" {
            Decision::Allow
        } else {
            Decision::Deny
        };
    }

    // R3: patient records — physicians & nurses of the SAME department
    // read; only physicians write; only physicians of the owning
    // department approve.
    if matches!(resource.kind, ResourceKind::PatientRecord) {
        let same_department = subject.department == resource.department;
        return match action {
            Action::Read
                if same_department && matches!(subject.role.as_str(), "physician" | "nurse") =>
            {
                Decision::Allow
            }
            Action::Write if same_department && subject.role == "physician" => Decision::Allow,
            Action::Approve if same_department && subject.role == "physician" => Decision::Allow,
            _ => Decision::Deny,
        };
    }

    Decision::Deny
}

pub fn decide(subject: &Subject, action: &Action, resource: &Resource) -> Decision {
    rules(subject, action, resource)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn physician(department: &str) -> Subject {
        Subject {
            user: "ada".into(),
            role: "physician".into(),
            department: department.into(),
        }
    }

    fn record(department: &str) -> Resource {
        Resource {
            kind: ResourceKind::PatientRecord,
            department: department.into(),
        }
    }

    #[test]
    fn same_department_physician_reads() {
        assert_eq!(
            decide(
                &physician("cardiology"),
                &Action::Read,
                &record("cardiology")
            ),
            Decision::Allow
        );
    }

    #[test]
    fn cross_department_denied() {
        assert_eq!(
            decide(&physician("oncology"), &Action::Read, &record("cardiology")),
            Decision::Deny
        );
    }

    #[test]
    fn nurses_read_but_never_write() {
        let nurse = Subject {
            user: "grace".into(),
            role: "nurse".into(),
            department: "cardiology".into(),
        };
        assert_eq!(
            decide(&nurse, &Action::Read, &record("cardiology")),
            Decision::Allow
        );
        assert_eq!(
            decide(&nurse, &Action::Write, &record("cardiology")),
            Decision::Deny
        );
        assert_eq!(
            decide(&nurse, &Action::Approve, &record("cardiology")),
            Decision::Deny
        );
    }

    #[test]
    fn audit_log_is_auditor_read_only() {
        let audit = Resource {
            kind: ResourceKind::AuditLog,
            department: "security".into(),
        };
        let auditor = Subject {
            user: "zed".into(),
            role: "auditor".into(),
            department: "security".into(),
        };
        assert_eq!(decide(&auditor, &Action::Read, &audit), Decision::Allow);
        assert_eq!(decide(&auditor, &Action::Write, &audit), Decision::Deny);
        assert_eq!(
            decide(&physician("security"), &Action::Read, &audit),
            Decision::Deny
        );
    }

    #[test]
    fn admin_only_system_config() {
        let config = Resource {
            kind: ResourceKind::SystemConfig,
            department: "platform".into(),
        };
        let admin = Subject {
            user: "root".into(),
            role: "admin".into(),
            department: "platform".into(),
        };
        assert_eq!(decide(&admin, &Action::Write, &config), Decision::Allow);
        assert_eq!(
            decide(&physician("platform"), &Action::Read, &config),
            Decision::Deny
        );
    }

    #[test]
    fn unknown_role_denied_everywhere() {
        let stranger = Subject {
            user: "x".into(),
            role: "intern".into(),
            department: "cardiology".into(),
        };
        assert_eq!(
            decide(&stranger, &Action::Read, &record("cardiology")),
            Decision::Deny
        );
    }
}
