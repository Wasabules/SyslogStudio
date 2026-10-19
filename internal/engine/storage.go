package engine

// The database: its settings, its statistics and the queries the history view runs.

import "SyslogStudio/internal/models"

// IsStorageReady returns true if the database is fully initialized (FTS index built).
func (e *Engine) IsStorageReady() bool {
	if e.logStore == nil {
		return false
	}
	return e.logStore.IsReady()
}

func (e *Engine) GetStorageConfig() models.StorageConfig {
	return e.withDBPath(e.configStore.LoadStorage())
}

func (e *Engine) SetStorageConfig(cfg models.StorageConfig) {
	e.configStore.SaveStorage(cfg)
	if e.logStore != nil {
		// The store resolves an empty path itself, against the user's
		// directory; filled in here so it is always the engine's.
		e.logStore.UpdateConfig(e.withDBPath(cfg))
	}
}

func (e *Engine) GetStorageStats() models.StorageStats {
	if e.logStore != nil {
		return e.logStore.GetStats()
	}
	return models.StorageStats{}
}

func (e *Engine) QueryMessages(opts models.QueryOptions) models.PagedResult {
	if e.logStore != nil {
		return e.logStore.QueryMessages(opts)
	}
	return models.PagedResult{Page: opts.Page, PageSize: opts.PageSize}
}

func (e *Engine) QueryMessageGroups(filter models.FilterCriteria, groupField string) []models.GroupSummary {
	if e.logStore != nil {
		return e.logStore.QueryGroups(filter, groupField)
	}
	return nil
}

func (e *Engine) CompactDatabase() error {
	if e.logStore != nil {
		return e.logStore.Compact()
	}
	return nil
}

func (e *Engine) ClearDatabase() error {
	if e.logStore != nil {
		return e.logStore.ClearAll()
	}
	return nil
}
