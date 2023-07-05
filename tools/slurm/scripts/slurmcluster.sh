#!/usr/bin/env bash
set -e

# This script is invoked by `make slurmcluster`. It should never be necessary to run it directly.

# Default values
export OPT_CONTAINER_RUN_TYPE="singularity"
export OPT_WORKLOAD_MANAGER="slurm"

while [[ $# -gt 0 ]]; do
    case $1 in
        -c | --container-run-type)
            export OPT_CONTAINER_RUN_TYPE=$2
            if [[ -z $OPT_CONTAINER_RUN_TYPE ]]; then
                echo >&2 "usage $0:  Missing -c {container_type}"
                exit 1
            fi
            shift 2
            ;;
        -w | --resource-manager)
            export OPT_WORKLOAD_MANAGER=$2
            if [[ -z $OPT_WORKLOAD_MANAGER ]]; then
                echo >&2 "usage $0:  Missing -r {workload_manager}"
                exit 1
            fi
            shift 2
            ;;
        # The Makefile that calls this script may pass in additional flags used for other scritps
        # which can be ignored.
        -t)
            shift 2
            ;;
        -h | --help)
            echo "Usage: $0 [flags=\"options\"]"
            echo ""
            echo "Launches a compute instance with Slurm, Singularity (Apptainer), the Cray"
            echo "Launcher component, and many other dependencies pre-installed. Then, SSH tunnels"
            echo "are opened so that localhost:8081 on your machine points at port 8081 on"
            echo "the compute instance and port 8080 on the compute instance points at"
            echo "localhost:8080 on your machine. Lastly, devcluster is started with the Slurm"
            echo "RM pointed at the remote instance, and local development with devcluster works"
            echo "as always."
            echo ""
            echo "flags:"
            echo '  -A: '
            echo "           Description: Invokes a slurmcluster that uses agents instead of the launcher."
            echo "           Example: $0 -A"
            echo '  -c: '
            echo "           Description: Invokes a slurmcluster using the specified container run type."
            echo "           Options are 'enroot', 'podman', or 'singularity'. Default is 'singularity'."
            echo "           Example: $0 -c podman"
            echo '  -w: '
            echo "           Description: Invokes a slurmcluster using the specified workload manager."
            echo "           Options are 'slurm' or 'pbs'. Default is 'slurm'."
            echo "           Example: $0 -w pbs"
            echo ""
            echo "You can also combine the flags."
            echo "Example: $0 -A -c enroot"
            echo ""
            exit 0
            ;;
        -* | --*)
            set +ex
            echo >&2 "$0: Illegal option $1"
            echo >&2 "Usage: $0 [-c {container_type}]"
            set -ex
            exit 1
            ;;
    esac
done

echo "Using ${OPT_CONTAINER_RUN_TYPE} as a container host"
echo "Using ${OPT_WORKLOAD_MANAGER} as a workload manager"

ZONE=$(terraform -chdir=terraform output --raw zone)
INSTANCE_NAME=$(terraform -chdir=terraform output --raw instance_name)
PROJECT=$(terraform -chdir=terraform output --raw project)
PARENT_PATH=$(
    cd "$(dirname "${BASH_SOURCE[0]}")"
    pwd -P
)
TEMPDIR=$(mktemp -d)
echo "Using tempdir $TEMPDIR"

# Wait for SSH (terraform returns before ssh is up).
echo "Trying SSH connection..."
until gcloud compute ssh --zone "$ZONE" "$INSTANCE_NAME" --project "$PROJECT" -- ls; do
    echo "Waiting 5s to try SSH again..."
    sleep 5
    echo "Retrying SSH connection..."
done
echo "SSH is up"

SOCKS5_PROXY_PORT=60000

SOCKS5_PROXY_TUNNEL_OPTS="-D ${SOCKS5_PROXY_PORT} -nNT"

# Launch SSH tunnels.
echo "Launching SSH tunnels"
gcloud compute ssh --zone "$ZONE" "$INSTANCE_NAME" --project "$PROJECT" -- -NL 8081:localhost:8081 -NR 8080:localhost:8080 ${SOCKS5_PROXY_TUNNEL_OPTS} &
TUNNEL_PID=$!
trap 'kill $TUNNEL_PID' EXIT
echo "Started bidirectional tunnels to $INSTANCE_NAME"

# Grab launcher token.
REMOTE_TOKEN_SOURCE=/opt/launcher/jetty/base/etc/.launcher.token
LOCAL_TOKEN_DEST=$TEMPDIR/.launcher.token
gcloud compute scp --zone "us-west1-b" --project "determined-ai" root@$INSTANCE_NAME:$REMOTE_TOKEN_SOURCE $LOCAL_TOKEN_DEST
echo "Copied launcher token to $LOCAL_TOKEN_DEST"

# Build devcluster.yaml.
gcloud_ssh() {
    gcloud compute ssh --zone "$ZONE" "$INSTANCE_NAME" --project "$PROJECT" -- $@ 2>/dev/null | tr -d '\r\n'
}

export OPT_REMOTE_UID=$(gcloud_ssh id -u)
export OPT_REMOTE_USER=$(gcloud_ssh id -un)
export OPT_REMOTE_GID=$(gcloud_ssh id -g)
export OPT_REMOTE_GROUP=$(gcloud_ssh id -gn)
export OPT_PROJECT_ROOT='../..'
export OPT_CLUSTER_INTERNAL_IP=$(terraform -chdir=terraform output --raw internal_ip)
export OPT_AUTHFILE=$LOCAL_TOKEN_DEST

CPU_IMAGE_STRING=$(grep "CPUImage" ../../master/pkg/schemas/expconf/const.go | awk -F'\"' '{print $2}')
CPU_IMAGE_FMT=${CPU_IMAGE_STRING//[\/:]/+}.sqsh

# Configuration needed for PBS + Enroot
if [[ $OPT_CONTAINER_RUN_TYPE == "enroot" ]]; then
    gcloud compute ssh --zone "$ZONE" "$INSTANCE_NAME" --project "$PROJECT" -- "sudo ENROOT_RUNTIME_PATH=/tmp ENROOT_TEMP_PATH=/tmp manage-enroot-cache -s /tmp ${CPU_IMAGE_STRING}"
    gcloud compute ssh --zone "$ZONE" "$INSTANCE_NAME" --project "$PROJECT" -- "enroot create --force /tmp/${CPU_IMAGE_FMT}"
    gcloud compute ssh --zone "$ZONE" "$INSTANCE_NAME" --project "$PROJECT" -- "sudo sed -i '/^#ENROOT_RUNTIME_PATH/c\ENROOT_RUNTIME_PATH        /tmp/\$\(whoami\)' /etc/enroot/enroot.conf"
fi

TEMPYAML=$TEMPDIR/slurmcluster.yaml
envsubst <$PARENT_PATH/slurmcluster.yaml >$TEMPYAML
echo "Generated devcluster file: $TEMPYAML"

# We connect to the Slurm VM using an external IP address, but although it's a
# single node cluster, the Determined master running on the test machine tries
# to connect to the shell container using its private 10.X.X.X address.
# Therefore, we must tell the Determined master to use the SOCKS5 proxy SSH
# tunnel that we configured so it can communicate with the container's private
# IP address.
#
# Note: Do not set ALL_PROXY before calling "gcloud" or it will fail.
export ALL_PROXY=socks5://localhost:${SOCKS5_PROXY_PORT}

# Run devcluster.
echo "Running cluster..."
devcluster -c $TEMPYAML --oneshot
