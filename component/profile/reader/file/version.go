/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package file

import (
	"fmt"
	"sort"

	"github.com/hashicorp/go-version"
)

const latest = "latest"

type profileVersionKey string

func getProfileVersionKey(profileID string, profileVersion *version.Version) profileVersionKey {
	k := fmt.Sprintf("%s_%s", profileID, profileVersion.String())

	return profileVersionKey(k)
}

func populateLatestTag[Profile any](
	profileVersions map[string]version.Collection,
	profileData map[profileVersionKey]Profile,
	store map[string]Profile) {
	for profileID, versions := range profileVersions {
		sort.Sort(versions)

		latestVersion := versions[len(versions)-1]
		latestMajorVersion := latestVersion.Segments()[0]
		// Set latest tag.
		store[fmt.Sprintf("%s_%s", profileID, latest)] =
			profileData[getProfileVersionKey(profileID, latestVersion)]
		// Set v<MAJOR>.latest tag for the latest version.
		store[fmt.Sprintf("%s_v%d.%s", profileID, latestMajorVersion, latest)] =
			profileData[getProfileVersionKey(profileID, latestVersion)]

		for i := versions.Len() - 1; i >= 0; i-- {
			currentVersion := versions[i]

			currentMajorVersion := currentVersion.Segments()[0]
			if currentMajorVersion < latestMajorVersion {
				latestMajorVersion = currentMajorVersion

				// Set v<MAJOR>.latest tag points to the most recent version of the current <MAJOR> version number.
				store[fmt.Sprintf("%s_v%d.%s", profileID, currentMajorVersion, latest)] =
					profileData[getProfileVersionKey(profileID, currentVersion)]
			}
		}
	}
}
