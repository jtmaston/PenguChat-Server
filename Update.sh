#!/bin/bash
branch=$1

echo "Updating from branch $branch"
git checkout "$branch"
git pull
systemctl restart PenguChatServer.service
systemctl status PenguChatServer.service