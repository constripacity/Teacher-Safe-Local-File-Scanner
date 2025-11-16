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

## 4. Create a safe Python environment

Copy and paste these commands into the terminal, one line at a time. Press Enter after each line.

```bash
python -m venv .venv
```

- On **Windows** run:
  ```cmd
  .venv\Scripts\activate
  ```
- On **macOS/Linux** run:
  ```bash
  source .venv/bin/activate
  ```

When the environment is active you will see `(.venv)` at the beginning of the terminal line.

## 5. Install the scanner

```bash
pip install -r requirements.txt
```

Wait until the installation finishes. If you see an error, ensure your internet connection is working and run the command again.

## 6. Create the example files

The repository avoids storing binary files, so you need to create the harmless samples locally. Run:

```bash
python examples/generate_benign_samples.py
```

This command creates three safe files inside `examples/benign_samples/`:

- `sample_text.txt` – a normal text file.
- `sample_image.png` – a tiny picture.
- `sample_docx.docx` – a Word document with no macros.

## 7. Run your first scan

```bash
python -m scanner scan examples/benign_samples
```

- If everything is safe, the program finishes with exit code `0` and prints a summary.
- If you ever see exit code `1`, `2`, or `3`, read the message shown on screen and follow the safety tips below.

## 8. What to do if something is flagged

1. **Do not open the file.**
2. Move it away from your main folders using:
   ```bash
   python -m scanner quarantine PATH_TO_FILE --dest quarantine
   ```
3. Share the JSON or HTML report with your school IT team.

## 9. Keep things up to date

- To update the scanner later, open the project folder, activate the virtual environment again, and run:
  ```bash
  git pull
  pip install -r requirements.txt
  ```
- Run the generator script again if you need fresh example files.

## 10. Extra help

- Read [README.md](README.md) for advanced features.
- Read [SAFETY.md](SAFETY.md) for more safety advice.
- If you are stuck, ask a colleague or your IT support team for help. Share any error messages exactly as they appear.

## Windows (PowerShell)

```powershell
py -3 -m venv .venv
. .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m scanner.gui
```

## macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m scanner.gui
```

Stay safe and never execute files that you do not fully trust.
