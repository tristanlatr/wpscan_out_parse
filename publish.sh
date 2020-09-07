#! /bin/bash
rm -rf ./dist
rm -fr ./build
rm -fr ./wpscan_out_parse.egg-info

python3 -m pdoc wpscan_out_parse --pdf --force > pdf.md
pandoc --metadata=title:"WPScan Out Parse Documentation" \
           --toc --toc-depth=4 --from=markdown+abbreviations \
           --pdf-engine=xelatex --variable=mainfont:"DejaVu Sans" \
           --output=docs.md --to=gfm pdf.md
git add DOCS.md
git commit -m "Generate docs"
rm -f pdf.md
git push

python3 setup.py build check sdist bdist_wheel
python3 -m twine upload --verbose dist/*

python3 setup.py clean
rm -rf ./dist
rm -fr ./build
rm -fr ./wpscan_out_parse.egg-info

