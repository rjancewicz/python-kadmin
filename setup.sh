#!/bin/bash

CWD=$(pwd)

GIT_SECRET_REPO_DST=$TMPDIR

if [ -f ./.git/hooks/pre-commit ] || [ -f ./.git/hooks/commit-msg ] || [ -f ./.git/hooks/prepare-commit-msg ]; then
    echo "ERROR: git hooks exist, please remove them before setting up"
    exit 1
fi

if [ ! -d $GIT_SECRET_REPO_DST/git-secrets ] ; then
    cd $GIT_SECRET_REPO_DST
    git clone https://github.com/awslabs/git-secrets.git
    cd git-secrets
    sudo make install
    cd ..
    rm -rf git-secrets
    cd $CWD
fi

cp ./hooks/* ./.git/hooks

git secrets --install -f # force install, this will overwrite pre-commit, prepare-commit-msg, and commit-msg in ./hooks
git secrets --register-aws --global # adds the git secrets to the global git config

if [ -f ./hooks/pre-commit ]; then
    cat ./hooks/pre-commit  | tail -n +2 >> ./.git/hooks/pre-commit
fi

if [ -f ./hooks/commit-msg ]; then
    cat ./hooks/commit-msg  | tail -n +2 >> ./.git/hooks/commit-msg
fi

if [ -f ./hooks/prepare-commit-msg ]; then
    cat ./hooks/prepare-commit-msg  | tail -n +2 >> ./.git/hooks/prepare-commit-msg
fi
