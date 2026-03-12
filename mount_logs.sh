if [ ! -d "./logs" ]; then
    mkdir -p ./logs
fi

sudo sshfs -o allow_other project01@cave.inf.ethz.ch:/mnt/SECTRS_POOL_0/USERDATA/BENEDICT/PROJECT_IBS ./logs