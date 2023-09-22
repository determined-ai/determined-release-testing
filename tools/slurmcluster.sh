#!/bin/bash
#
# This dev script is a wrapper on the devcluster tool, and provides
# per-user and per cluster configuration of the devcluster-slurm.yaml
# file to enable it to be used for our various clusters.  It dynamically
# fills in the variables within devcluster-slurm.yaml such that the original
# source need not be modified.   By default it also starts/stops SSH
# tunnels inbound to launcher, and outbound to the desktop master.
#
# It supports authorized access to the launcher by automatically specifying
# the auth_file if a ~/.{CLUSTER}.token file is present.   Use the -a option
# (one time) to retrieve a remote token file from the cluster.
#
# You can utilize a launcher instance created by the hpc-ard-capsule-core
# loadDevLauncher.sh script with the -d argument.
#
# Pre-requisites:
#   1) Configure your USERPORT_${USER} port below using your login name on
#      the desktop that you are using.
#
#   2)  Unless you specify both -n -x, you must have password-less ssh configured to the
#   target cluster, to enable the ssh connection without prompts.  Configure ~/.ssh/conf
#   to automatically configure your remote user name if your desktop username is
#   different than on the cluster.
#
#      ssh-copy-id {cluster}
#
#   3) To utilize the -a option to retrieve the /opt/launcher/jetty/base/etc/.launcher.token
#   you must have sudo access on the cluster, and authenticate the sudo that will be
#   exectued to retrieve the .launcher.token.

HELPEND=$((LINENO - 1))

INTUNNEL=1
TUNNEL=1
SOCKS5_PROXY_TUNNEL=1
DEVLAUNCHER=
USERNAME=$USER
DEBUGLEVEL=debug
SKIP_DEVCLUSTER_STAGE=0
# Variables that can be set before invoking the script (to change the default)
DEFAULTIMAGE=${DEFAULTIMAGE-}
SLOTTYPE=
DEFAULTCOMPUTERESOURCEPOOL=
# If empty use resource_manager: slurm|pbs, otherwise agent
DETERMINED_AGENT=

while [[ $# -gt 0 ]]; do
    case $1 in
        -n)
            INTUNNEL=
            shift
            ;;
        -x)
            TUNNEL=
            shift
            ;;
        --no-socks5-proxy)
            SOCKS5_PROXY_TUNNEL=
            shift
            ;;
        -t)
            DEBUGLEVEL=trace
            shift
            ;;
        -i)
            DEBUGLEVEL=info
            shift
            ;;
        -p)
            PODMAN=1
            shift
            ;;
        -e)
            ENROOT=1
            shift
            ;;
        -d)
            DEVLAUNCHER=1
            shift
            ;;
        -u)
            USERNAME=$2
            shift 2
            ;;
        -a)
            PULL_AUTH=1
            shift
            ;;
        -A)
            DETERMINED_AGENT=1
            shift
            ;;
        -c)
            DEFAULTIMAGE=$2
            shift 2
            ;;
        -r)
            DEFAULTCOMPUTERESOURCEPOOL=$2
            shift 2
            ;;
        --cpu)
            SLOTTYPE=cpu
            shift
            ;;
        --rocm)
            SLOTTYPE=rocm
            shift
            ;;
        -s)
            SKIP_DEVCLUSTER_STAGE=1
            shift
            ;;
        -h | --help)
            echo "Usage: $0 [-Aanxtpedcuis] [-c {image}] [-u {username}] [-r {rp}] {cluster}"
            echo "  -h                 This help message & documentation."
            echo "  -n                 Disable start of the inbound tunnel (when using Cisco AnyConnect)."
            echo "  -x                 Disable start of personal tunnel back to master (if you have done so manually)."
            echo "  --no-socks5-proxy  Disable start of SOCKS5 proxy SSH tunnel."
            echo "  -t                 Force debug level to trace regardless of cluster configuration value."
            echo "  -i                 Force debug level to INFO regardless of cluster configuration value."
            echo "  -p                 Use podman as a container host (otherwise singlarity)."
            echo "  -e                 Use enroot as a container host (otherwise singlarity)."
            echo "  -d                 Use a developer launcher (port assigned for the user in loadDevLauncher.sh)."
            echo "  -c                 Use the specified {image} as the default image.  Useful with -d and for enroot."
            echo "  --cpu              Force slot_type to cpu instead of the default (cuda)."
            echo "  -u                 Use provided {username} to lookup the per-user port number."
            echo "  -a                 Attempt to retrieve the .launcher.token - you must have sudo root on the cluster."
            echo "  -A                 Use agents instead of launcher to access HPC resources."
            echo "  -r                 Force a specified default compute resource pool."
            echo "  --rocm             Force slot_type to rocm instead of the default (cuda)."
            echo "  -s                 Do not launch the devcluster. The devcluster will need to be launched and managed separately. "
            echo "                     For example, e2e_slurm_restart tests manage their own instance of devcluster."
            echo
            echo "Documentation:"
            head -n $HELPEND $0 | tail -n $((HELPEND - 1))
            exit 1
            ;;
        -* | --*)
            echo >&2 "$0: Illegal option $1"
            echo >&2 "Usage: $0 [-anxtpde] [-c {image}] [-u {username}]  {cluster}"
            exit 1
            ;;
        *) # Non Option args
            CLUSTER=$1
            shift
            ;;
    esac
done

# Evaluate a dynamically constructed env variable name
function lookup() {
    echo "${!1}"
}

# Setup the reverse tunnel back to the master running locally
function mktunnel() {
    MASTER_HOST=$1
    MASTER_PORT=$2
    SSH_HOST=$3
    ssh -NR ${MASTER_HOST}:${MASTER_PORT}:localhost:8081 ${SSH_HOST}
}

# Setup the inbound tunnel to enable access to the launcher
function mkintunnel() {
    LAUNCHER_HOST=$1
    LAUNCHER_PORT=$2
    SSH_HOST=$3
    ssh -NL ${LAUNCHER_PORT}:${LAUNCHER_HOST}:${LAUNCHER_PORT} ${SSH_HOST}
}

# Setup a SOCKS5 proxy SSH tunnel to access any port on the compute nodes.
# This is needed when starting a Determined shell.
function mksocks5proxytunnel() {
    PROXY_PORT=$1
    SSH_HOST=$2
    ssh -D ${PROXY_PORT} -nNT ${SSH_HOST}
}

# Attempt to retrieve the auth token from the remote host
# This requires that your account have sudo access to root
# and will likely be prompted for a password.
# If launcherActualHost is specified, hostname will be used as ssh -oProxyJump={hostname}
# Args: {hostname} {clusterName} [launcherActualHost]
function pull_auth_token() {
    HOST=$1
    CLUSTER=$2
    ACTUAL=$3
    if [[ -n $ACTUAL ]]; then
        PROXY_OPT="-oProxyJump=$HOST"
        HOST=$ACTUAL
    fi

    echo "Attempting to access /opt/launcher/jetty/base/etc/.launcher.token from $HOST"
    rm -f ~/.token.log
    ssh $PROXY_OPT -t $HOST 'sudo cat /opt/launcher/jetty/base/etc/.launcher.token' | tee ~/.token.log
    # Token is the last line of the output (no newline)
    TOKEN=$(tail -n 1 ~/.token.log)
    if [[ ${TOKEN} != *" "* ]]; then
        echo -n "${TOKEN}" >~/.${CLUSTER}.token
        echo "INFO: Saved token as  ~/.${CLUSTER}.token"
    else
        echo "WARNING: No token retieved: ${TOKEN}" >&2
    fi
}

# Update your username/port pair
USERPORT_madagund=8083
USERPORT_laney=8084
USERPORT_rcorujo=8085
USERPORT_phillipgaisford=8086
USERPORT_mandalpa=8087
USERPORT_alyssa=8088
USERPORT_jerryharrow=8090
USERPORT_canmingcobble=8092
USERPORT_quilici=8093
USERPORT_tranc=8094
USERPORT_liuer=8108
USERPORT_wilsone=8888

USERPORT=$(lookup "USERPORT_$USERNAME")
if [[ -z $USERPORT ]]; then
    echo >&2 "$0: User $USERNAME does not have a configured port, update the script."
    exit 1
fi

# Re-map names that include - as variables with embedded - are treated as math expressions

if [[ $CLUSTER == "casablanca-login" ]]; then
    CLUSTER=casablanca_login
elif [[ $CLUSTER == "casablanca" ]]; then
    CLUSTER=casablanca_login
elif [[ $CLUSTER == "casablanca-mgmt1" ]]; then
    CLUSTER=casablanca_mgmt1
elif [[ $CLUSTER == "casablanca-login2" ]]; then
    CLUSTER=casablanca_login2
fi

# Update your JETTY HTTP username/port pair from loadDevLauncher.sh
DEV_LAUNCHER_PORT_madagund=18083
DEV_LAUNCHER_PORT_laney=18084
DEV_LAUNCHER_PORT_rcorujo=18085
DEV_LAUNCHER_PORT_phillipgaisford=18086
DEV_LAUNCHER_PORT_mandalpa=18087
DEV_LAUNCHER_PORT_alyssa=18088
DEV_LAUNCHER_PORT_jerryharrow=18090
DEV_LAUNCHER_PORT_canmingcobble=18092
DEV_LAUNCHER_PORT_quilici=18093
DEV_LAUNCHER_PORT_tranc=18094
DEV_LAUNCHER_PORT_liuer=18108
DEV_LAUNCHER_PORT_wilsone=18888
DEV_LAUNCHER_PORT=$(lookup "DEV_LAUNCHER_PORT_$USERNAME")

# SOCKS5 proxy port that will be used to create an SSH tunnel to access any port on the compute nodes
SOCKS5_PROXY_PORT_madagund=60000
SOCKS5_PROXY_PORT_laney=60001
SOCKS5_PROXY_PORT_rcorujo=60002
SOCKS5_PROXY_PORT_phillipgaisford=60003
SOCKS5_PROXY_PORT_mandalpa=60004
SOCKS5_PROXY_PORT_alyssa=60005
SOCKS5_PROXY_PORT_jerryharrow=60006
SOCKS5_PROXY_PORT_canmingcobble=60007
SOCKS5_PROXY_PORT_wilsone=60008
SOCKS5_PROXY_PORT_quilici=60009
SOCKS5_PROXY_PORT_tranc=60010
SOCKS5_PROXY_PORT_liuer=60018
SOCKS5_PROXY_PORT=$(lookup "SOCKS5_PROXY_PORT_$USERNAME")

# Configuration for atlas
OPT_name_atlas=atlas.us.cray.com
OPT_LAUNCHERPROTOCOL_atlas=http
OPT_CHECKPOINTPATH_atlas=/lus/scratch/foundation-engineering/determined-cp
OPT_MASTERHOST_atlas=atlas
OPT_MASTERPORT_atlas=$USERPORT
OPT_TRESSUPPORTED_atlas=false
OPT_GRESSUPPORTED_atlas=false
OPT_PROTOCOL_atlas=http

# Configuration for aizn-admin (via hpcgate proxy node)
OPT_name_aizn=hpcgate.us.rdlabs.hpecorp.net
OPT_LAUNCHERACTUALHOST_aizn=aizn-admin
OPT_LAUNCHERPROTOCOL_aizn=http
OPT_LAUNCHERPORT_aizn=8181
OPT_CHECKPOINTPATH_aizn=/home/launcher/.launcher/checkpoints
OPT_MASTERHOST_aizn=hpcgate
OPT_MASTERPORT_aizn=$USERPORT
OPT_PROTOCOL_aizn=http
OPT_DEFAULTIMAGE_aizn=

# Configuration for horizon
OPT_name_horizon=horizon.hpc.amslabs.hpecorp.net
OPT_LAUNCHERPORT_horizon=8181
OPT_LAUNCHERPROTOCOL_horizon=http
OPT_CHECKPOINTPATH_horizon=/lus/scratch/foundation_engineering/determined-cp
OPT_MASTERHOST_horizon=horizon
OPT_MASTERPORT_horizon=$USERPORT
OPT_TRESSUPPORTED_horizon=false
OPT_PROTOCOL_horizon=http

# Configuration for casablanca-mgmt1 (uses suffix casablanca_mgmt1)
OPT_name_casablanca_mgmt1=casablanca-mgmt1.hpc.amslabs.hpecorp.net
OPT_LAUNCHERPORT_casablanca_mgmt1=8181
OPT_LAUNCHERPROTOCOL_casablanca_mgmt1=http
OPT_CHECKPOINTPATH_casablanca_mgmt1=/mnt/lustre/foundation_engineering/determined-cp
OPT_MASTERHOST_casablanca_mgmt1=casablanca-mgmt1.hpc.amslabs.hpecorp.net
OPT_MASTERPORT_casablanca_mgmt1=$USERPORT
OPT_TRESSUPPORTED_casablanca_mgmt1=true

# Configuration for casablanca-login (uses suffix casablanca_login)
OPT_name_casablanca_login=casablanca-login.hpc.amslabs.hpecorp.net
OPT_LAUNCHERPORT_casablanca_login=8443
OPT_LAUNCHERPROTOCOL_casablanca_login=https
OPT_CHECKPOINTPATH_casablanca_login=/mnt/lustre/foundation_engineering/determined-cp
OPT_MASTERHOST_casablanca_login=casablanca-login
OPT_MASTERPORT_casablanca_login=$USERPORT
OPT_TRESSUPPORTED_casablanca_login=true
OPT_DEFAULTAUXRESOURCEPOOL_casablanca_login=
OPT_DEFAULTCOMPUTERESOURCEPOOL_casablanca_login=custom_defq_GPU
# Indentation of resource_pools must match devcluster-slurm.yaml
OPT_RESOURCEPOOLS_casablanca_login=$(
    cat <<EOF
        - pool_name: custom_defq_GPU
          description: Lands jobs on defq_GPU with tesla GPU (excluding non-GPU node009)
          task_container_defaults:
            slurm:
              gpu_type: tesla
              sbatch_args:
                - -xnode009
          provider:
            type: hpc
            partition: defq_GPU
EOF
)
# Indentation of partition_overrides must match devcluster-slurm.yaml
OPT_PARTITIONOVERRIDES_casablanca_login=$(
    cat <<EOF
             defq_GPU:
                description: Customized Slurm partition description
EOF
)

# Configuration for casablanca-login2 (uses suffix casablanca_login2)
OPT_name_casablanca_login2=casablanca-login2.hpc.amslabs.hpecorp.net
OPT_LAUNCHERPORT_casablanca_login2=8443
OPT_LAUNCHERPROTOCOL_casablanca_login2=http
OPT_CHECKPOINTPATH_casablanca_login2=/mnt/lustre/foundation_engineering/determined-cp
OPT_MASTERHOST_casablanca_login2=casablanca-login2
OPT_MASTERPORT_casablanca_login2=$USERPORT
OPT_TRESSUPPORTED_casablanca_login2=false
OPT_WLMTYPE_casablanca_login2=pbs

# Configuration for sawmill (10.100.97.101)
OPT_name_sawmill=10.100.97.101
OPT_LAUNCHERPROTOCOL_sawmill=http
OPT_CHECKPOINTPATH_sawmill=/scratch2/launcher/determined-cp
OPT_MASTERHOST_sawmill=nid000001
OPT_MASTERPORT_sawmill=$USERPORT
OPT_TRESSUPPORTED_sawmill=false
OPT_GRESSUPPORTED_sawmill=false
OPT_PROTOCOL_sawmill=http
OPT_DEFAULTIMAGE_sawmill=/scratch2/karlon/new/detAI-cuda-11.3-pytorch-1.10-tf-2.8-gpu-nccl-0.19.4.sif
# Indentation of task_container_defaults must match devcluster-slurm.yaml
OPT_TASKCONTAINERDEFAULTS_sawmill=$(
    cat <<EOF
          environment_variables:
            #- USE_HOST_LIBFABRIC=y
            - NCCL_DEBUG=INFO
            #- OMPI_MCA_orte_tmpdir_base=/dev/shm/
EOF
)
# Indentation of partition_overrides must match devcluster-slurm.yaml
OPT_PARTITIONOVERRIDES_sawmill=$(
    cat <<EOF
             grizzly:
                slot_type: cuda
             bard:
                slot_type: rocm
                task_container_defaults:
                    # New image with different bind-mounts
                    image:  /scratch2/beazley/rocm-5.6-pytorch-2.0-tf-2.10-rocm-0.24.0.1695406667.sif
                    bind_mounts:
                       - host_path: /
                         container_path: /DET_host
                       - host_path: /scratch2/crickett/lib/libfabric-1.21.1
                         container_path: /DET_fabric
                    environment_variables:
                       - MIOPEN_DEBUG_SAVE_TEMP_DIR=1               
EOF
)

# Configuration for shuco
OPT_name_shuco=shuco.us.cray.com
OPT_LAUNCHERPORT_shuco=8181
OPT_LAUNCHERPROTOCOL_shuco=http
OPT_CHECKPOINTPATH_shuco=/home/launcher/determined-cp
OPT_MASTERHOST_shuco=admin.head.cm.us.cray.com
OPT_MASTERPORT_shuco=$USERPORT
OPT_TRESSUPPORTED_shuco=false
OPT_PROTOCOL_shuco=http
OPT_RENDEVOUSIFACE_shuco=bond0

# Configuration for mosaic
OPT_name_mosaic=10.30.91.220
OPT_LAUNCHERPORT_mosaic=8181
OPT_LAUNCHERPROTOCOL_mosaic=http
OPT_CHECKPOINTPATH_mosaic=/home/launcher/determinedai/checkpoints
OPT_MASTERHOST_mosaic=10.30.91.220
OPT_MASTERPORT_mosaic=$USERPORT
OPT_TRESSUPPORTED_mosaic=false
OPT_PROTOCOL_mosaic=http
OPT_RENDEVOUSIFACE_mosaic=bond0
OPT_REMOTEUSER_mosaic=root@

# Configuration for osprey
OPT_name_osprey=osprey.us.cray.com
OPT_LAUNCHERPROTOCOL_osprey=http
OPT_CHECKPOINTPATH_osprey=/lus/scratch/foundation_engineering/determined-cp
OPT_DEBUGLEVEL_osprey=debug
OPT_MASTERHOST_osprey=osprey
OPT_MASTERPORT_osprey=$USERPORT
OPT_TRESSUPPORTED_osprey=false
OPT_PROTOCOL_osprey=http

# Configuration for vnode01 (vm-cluster1)
OPT_name_vnode01=10.30.90.125
OPT_LAUNCHERPROTOCOL_vnode01=http
OPT_CHECKPOINTPATH_vnode01=/shared/fe/determined-cp
OPT_DEBUGLEVEL_vnode01=debug
OPT_MASTERHOST_vnode01=10.30.90.125
OPT_MASTERPORT_vnode01=$USERPORT
OPT_TRESSUPPORTED_vnode01=false
OPT_PROTOCOL_vnode01=http

# Configuration for swan
OPT_name_swan=swan.hpcrb.rdlabs.ext.hpe.com
OPT_LAUNCHERPROTOCOL_swan=http
OPT_CHECKPOINTPATH_swan=/lus/scratch/foundation_engineering/determined-cp
OPT_MASTERHOST_swan=swan
OPT_MASTERPORT_swan=$USERPORT
OPT_TRESSUPPORTED_swan=false
OPT_PROTOCOL_swan=http

# Configuration for raptor
OPT_name_raptor=raptor.hpcrb.rdlabs.ext.hpe.com
OPT_LAUNCHERPROTOCOL_raptor=http
OPT_CHECKPOINTPATH_raptor=/lus/scratch/foundation_engineering/determined-cp
OPT_MASTERHOST_raptor=raptor
OPT_MASTERPORT_raptor=$USERPORT
OPT_TRESSUPPORTED_raptor=false
OPT_PROTOCOL_raptor=http

# Configuration for Genoble system o184i023 aka champollion (see http://o184i124.gre.smktg.hpecorp.net/~bench/)
# Need to request account to access these systems.   Managed GPUs include:
#
#  20 XL675d Gen10+ servers with 2x AMD EPYC 7763 processors (64c/2.45GHz/280W), 1TB/2TB RAM DDR4-3200 2R, 1x 3.2TB NVMe disk, 4x IB HDR ports, 8x NVIDIA A100/80GB SXM4 GPUs (*) -- aka 'Champollion'
#  4 XL270d Gen10 servers with Intel Cascade Lake Gold 6242 processors (16c/2.8GHz/150W), 384-768GB RAM DDR4-2400 2R, 1x basic 6G SFF SATA disk, 4x IB EDR ports, 8x NVIDIA V100/32GB SXM2 32GB GPUs (*)
#  1 XL675d Gen10+ server with 2x AMD EPYC 7543 processors (32c/2.8GHz/225W), 2TB RAM DDR4-3200 2R, 1x 1TB SFF SSD disk, 4x IB HDR ports, 10x NVIDIA A100/40GB PCIe GPUs (*)
#  1 XL675d Gen10+ server with 2x AMD EPYC 7763 processors (64c/2.45GHz/280W), 512GB RAM DDR4-3200 2R, 1x 1TB SFF SSD disk, 4x IB HDR ports, 8x AMD Mi210 PCIe/XGMI GPUs (*)
#  1 XL645d Gen10+ server with 2x AMD EPYC 7702 processors (64c/2.0GHz/200W), 512GB RAM DDR4-2666 2R, 1x 1.6TB NVMe disk, 1x IB EDR port, 4x NVIDIA A100/40GB PCIe GPUs (*)
#
OPT_name_o184i023=16.16.184.23
OPT_LAUNCHERPORT_o184i023=8181
OPT_LAUNCHERPROTOCOL_o184i023=http
OPT_CHECKPOINTPATH_o184i023=/cstor/harrow/determined-cp
OPT_MASTERHOST_o184i023=o184i023
OPT_MASTERPORT_o184i023=$USERPORT
OPT_TRESSUPPORTED_o184i023=false
OPT_GRESSUPPORTED_o184i023=false
OPT_PROTOCOL_o184i023=http
OPT_SLOTTYPE_o184i023=rocm

# Configuration for Grenobal o186i208 (o186i208.gre.smktg.hpecorp.net)
OPT_name_o186i208=o186i208.gre.smktg.hpecorp.net
OPT_LAUNCHERPORT_o186i208=8181
OPT_LAUNCHERPROTOCOL_o186i208=http
OPT_CHECKPOINTPATH_o186i208=/nfs/determined/checkpoints
OPT_MASTERHOST_o186i208=o186i208.gre.smktg.hpecorp.net
OPT_MASTERPORT_o186i208=$USERPORT
OPT_PROTOCOL_o186i208=http
OPT_DEFAULTCOMPUTERESOURCEPOOL_o186i20=mlde_cuda
# Indentation of task_container_defaults must match devcluster-slurm.yaml
OPT_TASKCONTAINERDEFAULTS_o186i208=$(
    cat <<EOF
          environment_variables:
            - NCCL_DEBUG=INFO
            - NCCL_SOCKET_IFNAME=ens,eth,ib
EOF
)
# Indentation of partition_overrides must match devcluster-slurm.yaml
OPT_PARTITIONOVERRIDES_o186i208=$(
    cat <<EOF
            mlde_rocm:
                slot_type: rocm
            gre1:
                slot_type: cpu
            gre2:
                slot_type: cpu
            gre4:
                slot_type: cpu
            genom_icx:
                slot_type: cpu
            hpfss:
                slot_type: cpu
            dev:
                slot_type: cpu
            misc_cpus:
                slot_type: cpu
EOF
)

# Configuration for Grenobal o184i054 (o184i054.gre.smktg.hpecorp.net)
OPT_name_o184i054=o184i054.gre.smktg.hpecorp.net
OPT_LAUNCHERPORT_o184i054=8181
OPT_LAUNCHERPROTOCOL_o184i054=http
OPT_CHECKPOINTPATH_o184i054=/cstor/determined/checkpoints
OPT_MASTERHOST_o184i054=o184i054.gre.smktg.hpecorp.net
OPT_MASTERPORT_o184i054=$USERPORT
OPT_PROTOCOL_o184i054=http
OPT_SLOTTYPE_o184i054=cuda
OPT_DEFAULTCOMPUTERESOURCEPOOL_o184i054=mlde_cuda
# Indentation of task_container_defaults must match devcluster-slurm.yaml
OPT_TASKCONTAINERDEFAULTS_o184i054=$(
    cat <<EOF
          environment_variables:
            - NCCL_DEBUG=INFO
            - NCCL_SOCKET_IFNAME=ens,eth,ib
EOF
)
# Indentation of partition_overrides must match devcluster-slurm.yaml
OPT_PARTITIONOVERRIDES_o184i054=$(
    cat <<EOF
            mlde_rocm:
                slot_type: rocm
            mlde_rocm_preempt:
                slot_type: rocm
            mlde_cpus:
                slot_type: cpu
            mlde_cpus_preempt:
                slot_type: cpu
            gre1:
                slot_type: cpu
            gre2:
                slot_type: cpu
            gre4:
                slot_type: cpu
            genom_icx:
                slot_type: cpu
            hpfss:
                slot_type: cpu
            dev:
                slot_type: cpu
            misc_cpus:
                slot_type: cpu
EOF
)
# Indentation of resource_pools must match devcluster-slurm.yaml
OPT_RESOURCEPOOLS_o184i054=$(
    cat <<EOF
        - pool_name: mlde_rocm_XL675d
          description: Use the o184i082 node with 8 AMD MI210 GPUs, 128 Cores, and 1 TiB of Memory
          provider:
            type: hpc
            partition: mlde_rocm
          task_container_defaults:
            slurm:
            #slots_per_node: 8
              sbatch_args:
                - --cpus-per-gpu=16
                - --mem-per-gpu=131072
                - --nodelist=o184i082
        - pool_name: mlde_cpus_XL225n
          description: Use the o184i[060-061] nodes with 256 AMD EPYC Milan 7713 Cores, and 512 GiB of Memory
          provider:
            type: hpc
            partition: mlde_cpus
          task_container_defaults:
            slurm:
            #slots_per_node: 256
              sbatch_args:
                - --nodelist=o184i[060-061]
EOF
)

# enroot-specific task container default if not otherwise defined
# Indentation of task_container_defaults must match devcluster-slurm.yaml
enroot_OPT_TASKCONTAINERDEFAULTS=$(
    cat <<EOF
          environment_variables:
            - ENROOT_RUNTIME_PATH=/tmp/\$\$(whoami)
EOF
)

# This is the list of options that can be injected into devcluster-slurm.yaml
# If a value is not configured for a specific target cluster, it will be
# blank and get the default value.   OPT_TASKCONTAINERDEFAULTS & OPT_PARTITIONOVERRIDES
# are multi-line values and must match the indentation of the associated
# section in devcluster-slurm.yaml.   See OPT_TASKCONTAINERDEFAULTS_sawmill as
# an example of how to provide such multi-line values.
export OPT_LAUNCHERHOST=$(lookup "OPT_LAUNCHERHOST_$CLUSTER")
export OPT_LAUNCHERACTUALHOST=$(lookup "OPT_LAUNCHERACTUALHOST_$CLUSTER")
export OPT_LAUNCHERPORT=$(lookup "OPT_LAUNCHERPORT_$CLUSTER")
export OPT_LAUNCHERPROTOCOL=$(lookup "OPT_LAUNCHERPROTOCOL_$CLUSTER")
export OPT_CHECKPOINTPATH=$(lookup "OPT_CHECKPOINTPATH_$CLUSTER")
export OPT_MASTERHOST=$(lookup "OPT_MASTERHOST_$CLUSTER")
export OPT_MASTERPORT=$(lookup "OPT_MASTERPORT_$CLUSTER")
export OPT_TRESSUPPORTED=$(lookup "OPT_TRESSUPPORTED_$CLUSTER")
export OPT_GRESSUPPORTED=$(lookup "OPT_GRESSUPPORTED_$CLUSTER")
export OPT_RENDEVOUSIFACE=$(lookup "OPT_RENDEVOUSIFACE_$CLUSTER")
export OPT_REMOTEUSER=$(lookup "OPT_REMOTEUSER_$CLUSTER")
export OPT_SLOTTYPE=$(lookup "OPT_SLOTTYPE_$CLUSTER")
export OPT_DEFAULTIMAGE=$(lookup "OPT_DEFAULTIMAGE_$CLUSTER")
export OPT_DEFAULTCOMPUTERESOURCEPOOL=$(lookup "OPT_DEFAULTCOMPUTERESOURCEPOOL_$CLUSTER")
export OPT_DEFAULTAUXRESOURCEPOOL=$(lookup "OPT_DEFAULTAUXRESOURCEPOOL_$CLUSTER")
export OPT_TASKCONTAINERDEFAULTS=$(lookup "OPT_TASKCONTAINERDEFAULTS_$CLUSTER")
export OPT_PARTITIONOVERRIDES=$(lookup "OPT_PARTITIONOVERRIDES_$CLUSTER")
export OPT_RESOURCEPOOLS=$(lookup "OPT_RESOURCEPOOLS_$CLUSTER")
export OPT_WLMTYPE=$(lookup "OPT_WLMTYPE_$CLUSTER")

# If WLM type has not been specified, default to  Slurm
if [[ -z $OPT_WLMTYPE ]]; then
    export OPT_WLMTYPE="slurm"
fi

if [[ -z $OPT_GRESSUPPORTED ]]; then
    export OPT_GRESSUPPORTED="true"
fi

if [[ -n $DEFAULTIMAGE ]]; then
    OPT_DEFAULTIMAGE=$DEFAULTIMAGE
else
    OPT_DEFAULTIMAGE=determinedai/environments:cuda-11.3-pytorch-1.12-tf-2.8-gpu-9d07809
fi

if [[ -n $SLOTTYPE ]]; then
    OPT_SLOTTYPE=$SLOTTYPE
fi

if [[ -n $DEFAULTCOMPUTERESOURCEPOOL ]]; then
    OPT_DEFAULTCOMPUTERESOURCEPOOL=$DEFAULTCOMPUTERESOURCEPOOL
fi

if [[ -n $DEVLAUNCHER ]]; then
    if [ -z $DEV_LAUNCHER_PORT ]; then
        echo >&2 "$0: User $USERNAME does not have a configured DEV_LAUNCHER_PORT, update the script."
        exit 1
    fi
    OPT_LAUNCHERPORT=$DEV_LAUNCHER_PORT
    # Currently devlauncher support config above only has http ports
    OPT_LAUNCHERPROTOCOL=http
fi

SLURMCLUSTER=$(lookup "OPT_name_$CLUSTER")
if [[ -z $SLURMCLUSTER ]]; then
    echo >&2 "$0: Cluster name $CLUSTER does not have a configuration. Specify one of:"
    echo >&2 "$(
        set -o posix
        set | grep OPT_name | cut -f 1 -d = | cut -c 10-
    )"
    exit 1
fi

if [[ -z $OPT_LAUNCHERPORT ]]; then
    echo >&2 "$0: Cluster name $CLUSTER does not have an installed launcher, specify -d to utilize a dev launcher."
    exit 1
fi

if [[ -n $PULL_AUTH ]]; then
    pull_auth_token ${OPT_REMOTEUSER}$SLURMCLUSTER $CLUSTER $OPT_LAUNCHERACTUALHOST
fi

if [[ -z $OPT_LAUNCHERACTUALHOST ]]; then
    # If not specified, the actual host of the launcher is the cluster master node
    # we are simulating.  This is the actual hostname of the launcher and is used
    # for the eventual destination of the tunnel.
    OPT_LAUNCHERACTUALHOST=$SLURMCLUSTER
fi

if [[ -z $INTUNNEL ]]; then
    # No tunnel, reference final actual host
    OPT_LAUNCHERHOST=$OPT_LAUNCHERACTUALHOST
else
    # We are setting up a tunnel, so the master.yaml needs to reference localhost
    OPT_LAUNCHERHOST=localhost
fi

export OPT_DEBUGLEVEL=$DEBUGLEVEL

if [[ -n $PODMAN ]]; then
    export OPT_CONTAINER_RUN_TYPE='podman'
fi

if [[ -n $ENROOT ]]; then
    export OPT_CONTAINER_RUN_TYPE='enroot'
    # If we have not otherwise setup OPT_TASKCONTAINERDEFAULTS, add default for Enroot
    # config to define ENROOT_RUNTIME_PATH
    if [[ -z $OPT_TASKCONTAINERDEFAULTS ]]; then
        OPT_TASKCONTAINERDEFAULTS=$enroot_OPT_TASKCONTAINERDEFAULTS
    fi
fi

if [[ -r ~/.${CLUSTER}.token ]]; then
    export OPT_AUTHFILE=~/.${CLUSTER}.token
fi

echo
echo "Configuration Used:"
printenv | grep OPT_
echo

# Terminate our tunnels on exit, only when SKIP_DEVCLUSTER_STAGE flag is not set
if [ $SKIP_DEVCLUSTER_STAGE -eq 0 ]; then
    trap "kill 0" EXIT
fi
if [[ -n $INTUNNEL || -n $TUNNEL || -n $SOCKS5_PROXY_TUNNEL ]]; then
    # Terminate any tunnels (non-interactive sshd proceses for the user)
    ssh ${OPT_REMOTEUSER}$SLURMCLUSTER pkill -u '$USER' -x -f '"^sshd: $USER[ ]*$"'
fi
if [[ -n $INTUNNEL ]]; then
    mkintunnel $OPT_LAUNCHERACTUALHOST $OPT_LAUNCHERPORT ${OPT_REMOTEUSER}$SLURMCLUSTER &
fi
if [[ -n $TUNNEL ]]; then
    mktunnel $OPT_MASTERHOST $OPT_MASTERPORT ${OPT_REMOTEUSER}$SLURMCLUSTER &
fi

if [[ -n $SOCKS5_PROXY_TUNNEL ]]; then
    mksocks5proxytunnel $SOCKS5_PROXY_PORT ${OPT_REMOTEUSER}$SLURMCLUSTER &

    # The Determined master needs this environment variable set in order
    # for shells to work. Of course, the SOCKS5 proxy SSH tunnel must be running,
    # which we created in the "mksocks5proxytunnel" above.
    export ALL_PROXY=socks5://localhost:${SOCKS5_PROXY_PORT}
fi

# Give a little time for the tunnels to setup before using
sleep 3

# Although devcluster supports variables, numeric values fail to load, so
# Manually apply those into a temp file.
TEMPYAML=/tmp/devcluster-$CLUSTER.yaml
rm -f $TEMPYAML

if [[ -n $DETERMINED_AGENT ]]; then
    # Clear custom resource pools as they they prevent the
    # default resource pool from being created and cause the agentRM to fail.
    unset OPT_RESOURCEPOOLS
fi
envsubst <tools/devcluster-slurm.yaml >$TEMPYAML
if [[ -n $DETERMINED_AGENT ]]; then
    # When deploying with the determined agent, remove the resource_manager section
    # that would otherwise be used.   This then defaults to the agent rm and
    # the master waits for agents to connect and provide resources.
    sed -i -e '/resource_manager/,/resource_manager_end/d' $TEMPYAML
fi

echo "INFO: Generated devcluster file: $TEMPYAML"
if [ $SKIP_DEVCLUSTER_STAGE -eq 0 ]; then
    devcluster -c $TEMPYAML --oneshot
else
    echo "INFO: Skipped devcluster stage. Any tunnels created will be alive until terminated manually."
fi
