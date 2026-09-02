# Benign test corpus

Every file here is harmless. Each one reproduces the *structure* of a risky
file so the detectors can be exercised without distributing malware.

| file | what it is meant to trigger |
| --- | --- |
| `Assignment.pdf.exe` | double extension on disk |
| `archive_double_extension.zip` | member disguised with a double extension |
| `archive_nested_deep.zip` | archives nested three levels deep |
| `archive_password_protected.zip` | archive marked as password protected (cannot be inspected) |
| `archive_path_traversal.zip` | member escapes the extraction folder |
| `archive_with_program.zip` | archive containing a runnable file |
| `archive_zip_bomb_shape.zip` | tiny archive that unpacks 48 MB (bomb ratio) |
| `broken_upload.zip` | truncated/corrupt archive |
| `clean_diagram.png` | ordinary PNG |
| `clean_essay.txt` | clean text file with an ordinary link |
| `clean_homework.zip` | ordinary archive of coursework |
| `clean_photo.jpg` | ordinary JPEG |
| `clean_report.docx` | ordinary Word document, no macros |
| `clean_worksheet.pdf` | ordinary PDF |
| `coursework.7z` | 7-Zip archive the scanner cannot open (reported as unchecked, not safe) |
| `empty_submission.docx` | zero-byte file |
| `essay.rtf` | RTF document the scanner cannot parse (reported as unchecked, not safe) |
| `image_is_really_a_program.jpg` | program renamed to .jpg |
| `image_large_appended.jpg` | JPEG with 600 KB appended after the end marker |
| `image_polyglot.png` | PNG with a real ZIP hidden after IEND |
| `invoice‮gpj.exe` | right-to-left override in the filename |
| `links_suspicious.txt` | text containing shortened, raw-IP and punycode links |
| `office_dde_field.docx` | document containing a DDE field |
| `office_embedded_object.docx` | document with an embedded object |
| `office_remote_template.docx` | document that loads a template from the internet |
| `office_renamed_program.docx` | program renamed to look like a Word file |
| `office_with_macro.docm` | document containing a macro project |
| `pdf_appended_payload.pdf` | PDF with a ZIP appended after %%EOF |
| `pdf_javascript.pdf` | PDF that runs JavaScript on open |
| `pdf_launch_action.pdf` | PDF that tries to launch a program |
