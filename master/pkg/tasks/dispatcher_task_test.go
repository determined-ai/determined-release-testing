package tasks

import (
	"archive/tar"
	"os"
	"reflect"
	"sort"
	"testing"

	"gotest.tools/assert"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/mount"

	"github.com/determined-ai/determined/master/pkg/archive"
	"github.com/determined-ai/determined/master/pkg/cproto"
	"github.com/determined-ai/determined/master/pkg/device"
	"github.com/determined-ai/determined/master/pkg/etc"
	"github.com/determined-ai/determined/master/pkg/model"
	"github.com/determined-ai/determined/master/pkg/schemas/expconf"
)

const workDir = "/workdir"

func TestTaskSpec_computeLaunchConfig(t *testing.T) {
	type args struct {
		slotType          device.Type
		workDir           string
		slurmPartition    string
		containerRunType  string
		disableImageCache bool
		addCaps           []string
		dropCaps          []string
		hostPaths         []string
		containerPaths    []string
		modes             []string
	}
	tests := []struct {
		name string
		args args
		want *map[string]string
	}{
		{
			name: "Dispatcher is notified that CUDA support required",
			args: args{
				slotType:       device.CUDA,
				workDir:        workDir,
				slurmPartition: "partitionName",
			},
			want: &map[string]string{
				"workingDir":          workDir,
				"enableNvidia":        trueValue,
				"enableWritableTmpFs": trueValue,
				"partition":           "partitionName",
			},
		},
		{
			name: "Dispatcher is notified that ROCM support required",
			args: args{
				slotType:       device.ROCM,
				workDir:        workDir,
				slurmPartition: "partitionName",
			},
			want: &map[string]string{
				"workingDir":          workDir,
				"enableROCM":          trueValue,
				"enableWritableTmpFs": trueValue,
				"partition":           "partitionName",
			},
		},
		{
			name: "Verify behavior when no partition specified, but using podman",
			args: args{
				slotType:         device.CUDA,
				workDir:          workDir,
				slurmPartition:   "",
				containerRunType: "podman",
			},
			want: &map[string]string{
				"workingDir":          workDir,
				"enableNvidia":        trueValue,
				"enableWritableTmpFs": trueValue,
				"networkMode":         "host",
			},
		},
		{
			name: "Verify behavior when image cache disabled & capabilities are being manipulated",
			args: args{
				slotType:          device.CUDA,
				workDir:           workDir,
				slurmPartition:    "",
				containerRunType:  "podman",
				disableImageCache: true,
				addCaps:           []string{"add1", "add2"},
				dropCaps:          []string{"drop1", "drop2"},
			},
			want: &map[string]string{
				"workingDir":          workDir,
				"enableNvidia":        trueValue,
				"enableWritableTmpFs": trueValue,
				"networkMode":         "host",
				"disableImageCache":   trueValue,
				"addCapabilities":     "add1,add2",
				"dropCapabilities":    "drop1,drop2",
			},
		},
		{
			name: "Verify behavior when devices are specified",
			args: args{
				workDir:          workDir,
				containerRunType: "podman",
				hostPaths:        []string{"/dev/one", "/dev/two"},
				containerPaths:   []string{"/dev/tr/1", "/dev/ctr/2"},
				modes:            []string{"", "abc"},
			},
			want: &map[string]string{
				"workingDir":          workDir,
				"enableWritableTmpFs": trueValue,
				"networkMode":         "host",
				"devices":             "/dev/one:/dev/tr/1:,/dev/two:/dev/ctr/2:abc",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			environment := expconf.EnvironmentConfigV0{
				RawImage:                &expconf.EnvironmentImageMapV0{},
				RawEnvironmentVariables: &expconf.EnvironmentVariablesMapV0{},
				RawPorts:                map[string]int{},
				RawRegistryAuth:         &types.AuthConfig{},
				RawForcePullImage:       &tt.args.disableImageCache,
				RawPodSpec:              &expconf.PodSpec{},
				RawSlurm:                []string{},
				RawAddCapabilities:      tt.args.addCaps,
				RawDropCapabilities:     tt.args.dropCaps,
			}

			tr := &TaskSpec{
				Environment: environment,
			}

			if len(tt.args.hostPaths) > 0 {
				devices := []expconf.DeviceV0{}
				for i, hostPath := range tt.args.hostPaths {
					device := expconf.DeviceV0{
						RawHostPath:      hostPath,
						RawContainerPath: tt.args.containerPaths[i],
						RawMode:          &tt.args.modes[i],
					}
					devices = append(devices, device)
				}
				tr.ResourcesConfig = expconf.ResourcesConfigV0{
					RawSlots:          new(int),
					RawMaxSlots:       new(int),
					RawSlotsPerTrial:  new(int),
					RawWeight:         new(float64),
					RawNativeParallel: new(bool),
					RawShmSize:        new(int),
					RawAgentLabel:     new(string),
					RawResourcePool:   new(string),
					RawPriority:       new(int),
					RawDevices:        devices,
				}
			}

			if got := tr.computeLaunchConfig(
				tt.args.slotType,
				tt.args.workDir,
				tt.args.slurmPartition,
				tt.args.containerRunType); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TaskSpec.computeLaunchConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_dispatcherArchive(t *testing.T) {
	err := etc.SetRootPath("../../static/srv/")
	assert.NilError(t, err)
	aug := &model.AgentUserGroup{
		ID:     1,
		UserID: 1,
		User:   "determined",
		UID:    0,
		Group:  "test-group",
		GID:    0,
	}

	want := cproto.RunArchive{
		Path: "/",
		Archive: archive.Archive{
			archive.Item{
				Path:     "/determined_local_fs/dispatcher-wrapper.sh",
				Type:     tar.TypeReg,
				FileMode: os.FileMode(0o700),
				UserID:   0,
				GroupID:  0,
			},
			archive.Item{
				Path:     "/run/determined",
				Type:     tar.TypeDir,
				FileMode: os.FileMode(0o700),
				UserID:   0,
				GroupID:  0,
			},
			archive.Item{
				Path:     "/run/determined/link-1",
				Type:     tar.TypeSymlink,
				FileMode: os.FileMode(0o700),
				UserID:   0,
				GroupID:  0,
			},
			archive.Item{
				Path:     "/run/determined/link-2",
				Type:     tar.TypeSymlink,
				FileMode: os.FileMode(0o700),
				UserID:   0,
				GroupID:  0,
			},
			archive.Item{
				Path:     "/run/determined/link-3",
				Type:     tar.TypeSymlink,
				FileMode: os.FileMode(0o700),
				UserID:   0,
				GroupID:  0,
			},
		},
	}

	got := dispatcherArchive(aug, []string{"link-1", "link-2", "link-3"})

	assert.Equal(t, got.Path, want.Path)
	assert.Equal(t, len(got.Archive), len(want.Archive))
	for i, a := range got.Archive {
		assert.Equal(t, a.Path, want.Archive[i].Path)
		assert.Equal(t, a.UserID, want.Archive[i].UserID)
		assert.Equal(t, a.GroupID, want.Archive[i].GroupID)
		assert.Equal(t, a.Type, want.Archive[i].Type)
		assert.Equal(t, a.FileMode, want.Archive[i].FileMode)
	}
}

func Test_generateRunDeterminedLinkNames(t *testing.T) {
	arg := []cproto.RunArchive{
		{
			Archive: archive.Archive{
				archive.Item{
					Path: "/determined_local_fs/dispatcher-wrapper.sh",
				},
				archive.Item{
					Path: "/" + etc.TaskLoggingSetupScriptResource,
				},
				archive.Item{
					Path: "/run/determined/link-1",
				},
				archive.Item{
					Path: "/run/determined/link-2",
				},
			},
		},
		{
			Archive: archive.Archive{
				archive.Item{
					Path: "/run/determined",
				},
				archive.Item{
					Path: "/run/determined/link-3",
				},
				archive.Item{
					Path: "/run/determined/xyz/abc.txt",
				},
			},
		},
	}

	want := []string{"link-1", "link-2", "link-3", "xyz"}

	got := generateRunDeterminedLinkNames(arg)

	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("generatedRunDeterminedLinkName = %v, want %v", got, want)
	}
}

func Test_getDataVolumns(t *testing.T) {
	arg := []mount.Mount{
		{
			Source: "xxx",
			Target: "yyy",
		},
		{
			Source: "aaa",
			Target: "bbb",
		},
		{
			Source: "/src",
			Target: "/tmp",
		},
	}

	wantName := []string{
		"ds0", "ds1", "ds2",
	}

	wantSource := []string{
		"xxx", "aaa", "/src",
	}

	wantTarget := []string{
		"yyy", "bbb", "/tmp",
	}

	volumns, mountOnTmp := getDataVolumes(arg)

	assert.Equal(t, mountOnTmp, true)
	for i, v := range volumns {
		assert.Equal(t, *v.Name, wantName[i])
		assert.Equal(t, *v.Source, wantSource[i])
		assert.Equal(t, *v.Target, wantTarget[i])
	}
}

func Test_getPayloadName(t *testing.T) {
	tests := []struct {
		name string
		desc string
		want string
	}{
		{
			name: "Test 1",
			desc: "abc_#123-&",
			want: "ai_abc_123-",
		},
		{
			name: "Test 2",
			desc: "   zyx-123 ",
			want: "ai_zyx-123",
		},
		{
			name: "Test 3",
			desc: "#sky , limit: .",
			want: "ai_skylimit",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &TaskSpec{}
			tr.Description = tt.desc
			got := getPayloadName(tr)
			assert.Equal(t, got, tt.want)
		})
	}
}
