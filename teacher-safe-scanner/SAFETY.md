# Safety & Ethics Guidance

Teacher-Safe Local File Scanner exists to reduce risk for teachers receiving student files. It must be used responsibly:

- **Defensive only:** The project must never be repurposed to build or distribute malicious tooling. Contributions that violate this principle will be rejected.
- **No execution:** The scanner reads metadata and file structures only. It never runs embedded macros, executables, or scripts.
- **Verification:** Treat scanner output as advisory. Confirm suspicious findings with professional antivirus or your institution’s security operations before taking disciplinary action.
- **Handling flagged files:**
  1. Quarantine the file using the provided command or another safe storage mechanism.
  2. Notify your IT or security team and share the generated reports.
  3. Review the file only inside an isolated sandbox with no network access.
  4. Document all actions for accountability and compliance.
- **Data privacy:** Reports may contain file paths or filenames. Store them securely and follow your school’s privacy requirements.

The maintainers welcome responsible disclosures and feedback via issues or pull requests.
