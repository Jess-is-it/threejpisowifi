# GitHub Workflow

- `staging` is for development and testing.
- `master` is production.
- Test deployment updates from `staging`.
- Production deployment updates from `master`.
- Merge `staging` into `master` only after manual acceptance testing passes.

Recommended flow:

```bash
git checkout staging
git pull
# make changes and test staging
git push origin staging
# after approval
git checkout master
git merge staging
git push origin master
```
