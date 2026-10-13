# Create the GitHub repository

After authorized review:

1. Create a new **private** repository named `KDP-Adapt-SSH-Empirical-Analysis` on GitHub.
2. Extract the package and open a terminal inside `KDP-Adapt-SSH-Empirical-Analysis/`.
3. Run `python scripts/privacy_audit.py` and `python scripts/analyze.py`.
4. Initialize and push the **clean exported folder**, not any parent/private source folder:

```bash
git init
git add .
git diff --cached --stat
git commit -m "Add privacy-reduced SSH empirical reproducibility package"
git branch -M main
git remote add origin https://github.com/ACCOUNT/KDP-Adapt-SSH-Empirical-Analysis.git
git push -u origin main
```

5. Inspect the GitHub file tree and commit contents again. Switch visibility to **public** only
   after authorization to release and after selecting suitable licenses.

No original data and no raw command/payload examples should enter the repository or its history.
