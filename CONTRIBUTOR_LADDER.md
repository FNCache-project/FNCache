# FNCache Contributor Ladder

## 1. Purpose and Scope

This document defines contributor roles, progression paths, and GitHub repository permission mappings for the FNCache project.

The `FNCache-project` organization serves only the FNCache core project and its official ecosystem projects. This document applies to the core repositories owned by the organization and to official ecosystem repositories added to the organization in the future.

This document defines project roles and permission principles; it does not replace GitHub's specific settings. GitHub repository permissions are used to enforce the minimum-permission boundaries described here.

## 2. Core Principles

1. Contributor is the default status; it does not require organization membership or GitHub repository permissions.
2. Organization membership and specific repository permissions are managed separately; joining the organization does not automatically grant high-level permissions across all repositories.
3. Permissions are granted progressively based on actual contributions and responsibilities, following the principle of least privilege.
4. Reviewer permissions are limited to explicitly designated repositories and modules.
5. Admin is a high-risk repository administration permission, not a required level in the normal contributor progression path.
6. Records of role grants, changes, and revocations should be retained for auditability.
7. Public contributions do not require an organization invitation in advance.

## 3. Roles and GitHub Permissions

| Project role | Organization status | Specific repository permission | Primary capabilities |
| --- | --- | --- | --- |
| Contributor | Non-organization member | No additional permissions | Fork, Issue, Discussion, Pull Request |
| Member | Organization Member | Triage | Manage Issues/PRs, labels, assignments, and review requests |
| Reviewer | Organization Member | Write | Review, approve, or request changes to PRs within designated modules |
| Maintainer | Organization Member | Maintain | Maintain repositories, merge qualifying PRs, and participate in project maintenance |
| Admin | Organization Member or Organization Owner | Admin | Repository settings, permissions, and high-risk or emergency operations |

GitHub's `Read`, `Triage`, `Write`, `Maintain`, and `Admin` are repository permissions; Contributor, Member, Reviewer, Maintainer, and Admin are FNCache project roles. The two are mapped through the table above but should not be treated as the same concept.

Organization Owner is an organizational infrastructure administration identity, not part of the contributor progression path. An Organization Owner is responsible for organization members, repositories, and security settings, but does not automatically assume the technical responsibilities of an FNCache Maintainer.

## 4. Contributor

### 4.1 Definition

A Contributor is anyone who participates in public FNCache collaboration but has not received organization membership. This is the default status and does not require manual assignment by a project administrator.

### 4.2 Ways to Participate

A Contributor may:

- Fork public repositories;
- Report Issues;
- Participate in Discussions;
- Submit Pull Requests;
- Submit tests, documentation, issue analysis, or design suggestions.

A Contributor does not have organization member permissions and cannot push directly to protected branches.

## 5. Member

### 5.1 Definition

A Member is an organization member who has been invited to and accepted membership in `FNCache-project`. Member status means the project has established a foundation of trust in the person's continued collaboration and community participation.

### 5.2 Promotion Criteria

The following conditions are normally required:

- Participate continuously in the project for at least 3 months;
- Complete at least 5 substantive contributions, or 1–2 large contributions with clear scope and impact;
- Participate in collaborative activities such as Issue analysis, testing, documentation, or Pull Request reviews;
- Receive recognition from two existing Members.

“Substantive contribution” includes effective code, bug fixes, tests, reproductions, design analysis, documentation, release materials, and high-quality reviews; mechanical commit count alone is not the sole criterion.

### 5.3 Permissions

Once granted permissions for a specific repository, a Member usually corresponds to GitHub `Triage`:

- Manage labels and assignments for Issues and Pull Requests;
- Request reviews from Reviewers;
- Help organize and close resolved issues;
- Participate in project collaboration management.

A Member cannot push code directly, approve merges, or modify repository administration settings.

## 6. Reviewer

### 6.1 Definition

A Reviewer is responsible for reviewing designated repositories and modules. Reviewer is not a global role with default approval authority over an entire repository.

### 6.2 Promotion Criteria

- Be approved by two existing Maintainers;
- Have the responsible repository and module scope explicitly recorded;
- Be able to understand and review the module's implementation, tests, and design constraints.

### 6.3 Permissions and Responsibilities

In the target repository, a Reviewer usually corresponds to GitHub `Write`:

- Review Pull Requests for designated modules;
- Approve or request changes to in-scope Pull Requests;
- Push to unprotected branches for fixes or collaboration;
- Participate in module design and test-quality maintenance.

A Reviewer must not approve their own Pull Request or use module permissions to modify unrelated areas. Cross-module changes require joint review by the relevant module Reviewer or Maintainer.

A Reviewer's approval becomes a merge gate only when the repository's branch protection rules require the corresponding review.

## 7. Maintainer

### 7.1 Definition

A Maintainer is responsible for the day-to-day technical maintenance and quality control of one or more repositories.

### 7.2 Promotion Criteria

- Be nominated by an existing Maintainer;
- Be supported by lazy consensus among the existing Maintainers;
- Be able to continuously take responsibility for code review, issue handling, testing, and release collaboration.

### 7.3 Permissions and Responsibilities

In the target repository, a Maintainer usually corresponds to GitHub `Maintain`:

- Maintain repository collaboration processes;
- Merge Pull Requests that meet review and testing requirements;
- Coordinate cross-module changes;
- Participate in role grants, permission adjustments, and release preparation;
- Maintain the repository's technical quality and documentation consistency.

`Maintain` does not equal repository `Admin`. High-risk repository settings, permission management, Webhooks, Deploy Keys, repository deletion, and repository transfers remain within the Admin scope.

## 8. Admin

### 8.1 Definition

Admin is a repository-level high-risk administration permission used for security, permission, configuration, and emergency operations.

Admin is not a required level in the normal contributor progression path and does not automatically represent final decision-making authority over the project's technical direction.

### 8.2 Scope of Use

An Admin may perform:

- Repository permission and settings management;
- Branch protection and rule maintenance;
- Webhook, Deploy Key, and integration management;
- High-risk operations such as repository transfers, archiving, or deletion;
- Security incident response and emergency recovery.

Admin permissions should be granted to a small number of trusted people, and an audit trail of operations should be retained. Routine code merges should preferably be performed with Maintainer permissions.

## 9. Repository Scope and Ecosystem Projects

Role permissions are granted separately for each repository. A person may have different roles in different repositories:

- Maintainer in the core repository;
- Reviewer in an ecosystem repository;
- Contributor in an experimental repository.

Joining `FNCache-project` does not automatically grant Triage, Write, Maintain, or Admin permissions for all future repositories.

Reviewer permissions should also be bound to actual modules, such as the datapath, control plane, or platform testing. Full-repository Reviewer permissions should not be granted before clear module responsibility is established.

## 10. Promotion, Demotion, and Revocation

### 10.1 Sponsor

- A Sponsor must be at the same level as or higher than the target role;
- A Sponsor must not be the applicant;
- Anyone with a conflict of interest should recuse themselves;
- The promotion basis, Sponsor, and final decision should be retained for auditability.

### 10.2 Permission Changes

The following circumstances may trigger demotion, suspension, or revocation:

- No longer participating in project maintenance for an extended period;
- Voluntarily requesting to leave the role;
- Violating security, review, or permission boundaries;
- Repeatedly bypassing the project's required testing or review processes;
- The role's responsibilities being transferred to another maintainer.

Revoking repository permissions does not delete the record of past contributions. People who temporarily step away from maintenance may retain their contribution records and reapply for the corresponding role when they resume responsibility.

## 11. Related GitHub Configuration Principles

- Organizational identities distinguish only between Organization Owner and Organization Member;
- Contributors do not need to join the organization;
- Repository permissions for Members, Reviewers, Maintainers, and Admins are granted separately for each repository;
- Creating Teams is not required at the current stage;
- Protected branches, CODEOWNERS, and CI are technical enforcement mechanisms for permission rules and do not change the role definitions in this document;
- Any repository permission change should remain consistent with the role records in this document.
