#! /bin/bash
rm -rf ./dist
rm -fr ./build
rm -fr ./wpscan_out_parse.egg-info

python3 -m pdoc wpscan_out_parse --pdf --force > DOCUMENTATION.md
git add DOCUMENTATION.md
git commit -m "Generate docs"
git push

python3 setup.py build check sdist bdist_wheel
python3 -m twine upload --verbose dist/*

python3 setup.py clean
rm -rf ./dist
rm -fr ./build
rm -fr ./wpscan_out_parse.egg-info