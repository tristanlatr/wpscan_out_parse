# Run pydoctor build
pydoctor \
        --add-package=wpscan_out_parse \
        --project-name="WPScan Output Parser" \
        --project-url=https://github.com/$GITHUB_REPOSITORY \
        --html-viewsource-base https://github.com/$GITHUB_REPOSITORY/tree/$GITHUB_SHA \
        --make-html \
        --html-output=./apidocs \
        --project-base-dir "$(pwd)" \
        --docformat=restructuredtext