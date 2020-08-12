#! /bin/bash
rm -rf ./dist
rm -fr ./build
rm -fr ./wpscan_out_parse.egg-info
python3 setup.py build check sdist bdist_wheel
python3 -m twine upload --verbose dist/*
python3 setup.py clean
rm -rf ./dist
rm -fr ./build
rm -fr ./wpscan_out_parse.egg-info