package dispatcherrm

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"github.hpe.com/hpe/hpc-ard-launcher-go/launcher"

	"github.com/determined-ai/determined/master/internal/db"
	"github.com/determined-ai/determined/master/pkg/tasks"
)

const (
	// Delay before gcOrphanedDispatches starts its work.
	gcDelay = 15 * time.Minute
)

// Possible names of dispatcher jobs generated by dispatcher RM.
var ourJobNames = []string{tasks.ManifestName, resourceQueryName, queueQueryName}

// isForeignJob returns true if the HPC job has name but is not one of the names
// employed by the dispatcher RM.
func isForeignJob(v launcher.DispatchInfo) bool {
	jobName := v.GetLaunchedCapsuleReference().Name
	if jobName == nil || *jobName == "" {
		// if missing dispatch name file or name is empty, we delete it
		return false
	}
	for _, ourName := range ourJobNames {
		if *jobName == ourName {
			return false
		}
	}
	return true
}

// gcOrphanedDispatches is a background method to do
// a single garbage collection of orhaned dispatches.  Such
// orphaned dispatches should be rare in normal circumstances, but
// due to defects, communication errors with the launcher, or
// changes to the job_storage_root configuraition we may have unused
// dispatches stored by the launcher.   Excessive unused dispatches
// take up disk space, and increases search time for certain launcher
// operations.  This method waits for gcDelay time beforing doing its
// work to reduce impact on startup time.   It does a terminate of
// on all orphaned running dispatches (orphaned PENDING/RUNNING need an
// explicit termination to get to a terminated state -- in case there is no
// job ID to check).   It then deletes all orphaned terminated dispatches.
// Once gc completes, the  routine terminates.
func gcOrphanedDispatches(
	ctx context.Context,
	log *logrus.Entry,
	cl *launcherAPIClient,
) {
	time.Sleep(gcDelay)
	gcTerminateRunningOrphans(ctx, log, cl)
	gcTerminatedOrphans(ctx, log, cl)
}

// refreshRunningOrphans requests the launcher to terminate and update the state of
// all dispatches not currently in-use by Determined as identified by the entries in the db.
// This enables safe gc of terminated jobs using the gcTerminated method.
func gcTerminateRunningOrphans(
	ctx context.Context,
	log *logrus.Entry,
	cl *launcherAPIClient,
) {
	// The logger we will pass to the API client, so that when the API client
	// logs a message, we know who called it.
	launcherAPILogger := log.WithField("caller", "gcTerminateRunningOrphans")

	data, _, err := cl.listAllRunning(launcherAPILogger) //nolint:bodyclose
	if err != nil {
		log.WithError(err).Warn("unable to list running dispatches, skipping status refresh for gc")
		return
	}

	dispatches := data["data"]
	log.Infof("gc found %d running dispatches", len(dispatches))
	for _, v := range dispatches {
		dispatchID := v.GetDispatchId()
		if isForeignJob(v) {
			log.WithField("dispatch-id", dispatchID).
				WithField("name", *v.LaunchedCapsuleReference.Name).
				Debug("skipping foreign dispatch")
			continue
		}
		_, err := db.DispatchByID(ctx, dispatchID)
		if err == nil {
			log.WithField("dispatch-id", dispatchID).
				WithField("state", v.GetState()).
				Debug("dispatch still referenced")
			continue
		}

		owner := *v.GetLaunchedCapsuleReference().Owner
		log.WithField("dispatch-id", dispatchID).
			WithField("owner", owner).
			WithField("state", v.GetState()).
			Info("terminate dispatch")
		_, _, err = cl.terminateDispatch( //nolint:bodyclose
			owner,
			dispatchID,
			launcherAPILogger)
		if err != nil {
			log.WithField("dispatch-id", dispatchID).
				WithError(err).Warn("unable to terminate dispatch")
			continue
		}

		dispatch, _, err := cl.getEnvironmentStatus(owner, dispatchID, launcherAPILogger) //nolint:bodyclose
		if err != nil {
			log.WithField("dispatch-id", dispatchID).
				WithError(err).Warn("unable to refresh dispatch status")
		} else {
			log.WithField("dispatch-id", dispatchID).
				WithField("owner", owner).
				WithField("state", dispatch.GetState()).
				Infof("refreshed dispatch")
		}
	}
}

// gcTerminatedOrphans processes all terminated dispatches and deletes any that are
// not referenced in the determined db.
func gcTerminatedOrphans(
	ctx context.Context,
	log *logrus.Entry,
	cl *launcherAPIClient,
) {
	// The logger we will pass to the API client, so that when the API client
	// logs a message, we know who called it.
	launcherAPILogger := log.WithField("caller", "gcTerminatedOrphans")

	data, _, err := cl.listAllTerminated(launcherAPILogger) //nolint:bodyclose
	if err != nil {
		log.WithError(err).Warn("unable to list terminated dispatches, skipping dispatch gc")
		return
	}

	dispatches := data["data"]
	log.Infof("gc found %d terminated dispatches", len(dispatches))

	for _, v := range dispatches {
		dispatchID := v.GetDispatchId()
		if isForeignJob(v) {
			log.WithField("dispatch-id", dispatchID).
				WithField("name", *v.LaunchedCapsuleReference.Name).
				Debug("skipping foreign dispatch")
			continue
		}
		_, err := db.DispatchByID(ctx, dispatchID)
		if err == nil {
			log.WithField("dispatch-id", dispatchID).
				Debug("gc dispatch still referenced")
			continue
		}

		owner := *v.GetLaunchedCapsuleReference().Owner
		log.WithField("dispatch-id", dispatchID).
			WithField("owner", owner).
			WithField("state", v.GetState()).
			Infof("gc dispatch")
		_, err = cl.deleteDispatch(owner, dispatchID, launcherAPILogger) //nolint:bodyclose
		if err != nil {
			log.WithField("dispatch-id", dispatchID).
				WithField("owner", owner).
				WithError(err).Errorf("unable to gc dispatch")
		}
	}
}
