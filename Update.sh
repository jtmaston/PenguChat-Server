#!/bin/bash
branch=$1

echo "Updating from branch $branch"
git checkout "$branch"
git pull
systemctl reload PenguChatServer.service
systemctl status PenguChatServer.service