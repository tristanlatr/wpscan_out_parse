#! /bin/bash
rm -rf ./dist
rm -fr ./build
rm -fr ./wpscan_out_parse.egg-info

python3 -m pdoc wpscan_out_parse.__init__ --pdf --force > pdf.md
pandoc --metadata=title:"WPScan Out Parse Documentation" \
           --toc --toc-depth=4 --from=markdown+abbreviations \
           --output=docs.md --to=gfm pdf.md
sleep 2
git add docs.md
git commit -m "Generate docs.md"
rm -f pdf.md
git push

python3 setup.py build check sdist bdist_wheel
python3 -m twine upload --verbose dist/*

python3 setup.py clean
rm -rf ./dist
rm -fr ./build
rm -fr ./wpscan_out_parse.egg-info

