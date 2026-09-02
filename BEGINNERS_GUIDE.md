# Beginner Guide: Teacher-Safe Local File Scanner

This guide is for people who are new to computers and want a safe way to check student files before opening them. Every step is written as plainly as possible.

## 1. What you need

- A computer with Windows, macOS, or Linux.
- Python 3.10 or newer. If you are not sure, open a terminal (Command Prompt on Windows) and type `python --version`.
- About 15 minutes to follow the steps.

## 2. Download the project

1. Open your web browser.
2. Visit the project page and click **Code → Download ZIP**.
3. Unzip the file into a folder you can find easily, such as `Documents/teacher-safe-scanner`.

## 3. Open a terminal in the project folder

- **Windows:** Open the Start menu, type **Command Prompt**, press Enter, then run:
  ```cmd
  cd %HOMEPATH%\Documents\teacher-safe-scanner
  ```
- **macOS:** Open Spotlight (⌘ + Space), type **Terminal**, press Enter, then run:
  ```bash
  cd ~/Documents/teacher-safe-scanner
  ```
- **Linux:** Open your terminal app and type:
  ```bash
  cd ~/Documents/teacher-safe-scanner
  ```

If the terminal says "The system cannot find the path specified" or "No such file or directory", double-check the folder location and try again.

## 4. Install what you need — probably nothing

The scanner needs **no extra software**. It uses only what comes with Python.

If you want the desktop window as well, you may need one extra package:

- **Windows and macOS:** nothing to do. It is already included.
- **Debian, Ubuntu, Mint:** `sudo apt install python3-tk`
- **Fedora:** `sudo dnf install python3-tkinter`

## 5. Try it on the practice files first

The project ships with a folder of harmless practice files. They are completely
safe — they are ordinary text and pictures built to *look* like risky files, so
you can see what the scanner does before you use it on real work.

```
python examples/generate_benign_samples.py
python -m scanner scan examples/benign_samples
```

You should see a list where most files are marked **DO NOT OPEN** and a few are
marked **LIKELY SAFE**. That is correct: most of the practice files are supposed
to be caught.

## 6. Check some real submissions

Put the files you want to check into one folder. Then:

```
python -m scanner scan "C:\Users\you\Downloads\period-3" --report-html report.html
```

On macOS or Linux:

```
python -m scanner scan ~/Downloads/period-3 --report-html report.html
```

Open `report.html` by double-clicking it. It opens in your web browser. It is a
single file — you can email it to your IT team.

## 7. Reading the result

| What you see | What it means | What to do |
| --- | --- | --- |
| ✓ **LIKELY SAFE TO REVIEW** | Nothing was found | Open it normally |
| ! **REVIEW WITH CAUTION** | Something is worth a look | Read the reason before opening |
| ✖ **DO NOT OPEN — CONTACT IT** | Something clearly risky was found | Do not open it. Send the report to IT |
| ? **COULD NOT FULLY INSPECT** | The scanner could not see inside | Treat it as unchecked, **not** as safe |

Under each file, the report explains in plain words what was found, why it
matters, and what to do. You can forward those sentences to a colleague or a
parent as they are.

## 8. If you want to open a window instead of typing commands

```
python -m scanner gui
```

Choose a folder, press **Scan**, and click any row to see the details. The
**Copy summary for IT** button puts a plain-text summary on your clipboard.

## 9. Moving risky files out of the way

If you want the flagged files moved somewhere they cannot be opened by accident:

```
python -m scanner scan ~/Downloads/period-3 --quarantine-dir ~/Documents/quarantine
```

**Nothing is ever deleted.** The files are moved, renamed so a double-click does
nothing, and written down in a list. To get one back:

```
python -m scanner quarantine-list --dest ~/Documents/quarantine
python -m scanner restore <the id shown> --dest ~/Documents/quarantine
```

## 10. Important things to remember

- This is **not** antivirus. Keep using whatever your school already installs.
- "Likely safe" means *nothing was found*, not *this is definitely fine*.
- The scanner never opens or runs the files it checks, and nothing is ever sent
  over the internet. Student work stays on your computer.
- If a file is marked **DO NOT OPEN**, send the report to your IT team — not the
  file itself.

## Getting help

If something does not work, open an issue on the project page and paste what you
typed and what you saw. Do not attach the student file.
