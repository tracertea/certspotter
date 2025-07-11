// Copyright (C) 2023 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package monitor

import (
	"context"
	"fmt"
	"github.com/tracertea/src/certspotter/cttypes"
	"github.com/tracertea/src/certspotter/loglist"
)

type LogID = cttypes.LogID

func getLogList(ctx context.Context, source string, token *loglist.ModificationToken) (map[LogID]*loglist.Log, *loglist.ModificationToken, error) {
	list, newToken, err := loglist.LoadIfModified(ctx, source, token)
	if err != nil {
		return nil, nil, err
	}

	logs := make(map[LogID]*loglist.Log)
	for operatorIndex := range list.Operators {
		for logIndex := range list.Operators[operatorIndex].Logs {
			log := &list.Operators[operatorIndex].Logs[logIndex]
			if _, exists := logs[log.LogID]; exists {
				return nil, nil, fmt.Errorf("log list contains more than one entry with ID %s", log.LogID.Base64String())
			}
			logs[log.LogID] = log
		}
		for logIndex := range list.Operators[operatorIndex].TiledLogs {
			log := &list.Operators[operatorIndex].TiledLogs[logIndex]
			if _, exists := logs[log.LogID]; exists {
				return nil, nil, fmt.Errorf("log list contains more than one entry with ID %s", log.LogID.Base64String())
			}
			logs[log.LogID] = log
		}
	}
	return logs, newToken, nil
}
