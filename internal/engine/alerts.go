package engine

// Alert rules and the history of what they caught.

import "SyslogStudio/internal/models"

func (e *Engine) GetAlertRules() []models.AlertRule {
	return e.server.AlertManager.GetRules()
}

func (e *Engine) AddAlertRule(rule models.AlertRule) models.AlertRule {
	r := e.server.AlertManager.AddRule(rule)
	e.configStore.SaveAlertRules(e.server.AlertManager.GetRules())
	return r
}

func (e *Engine) UpdateAlertRule(rule models.AlertRule) bool {
	ok := e.server.AlertManager.UpdateRule(rule)
	if ok {
		e.configStore.SaveAlertRules(e.server.AlertManager.GetRules())
	}
	return ok
}

func (e *Engine) DeleteAlertRule(id string) bool {
	ok := e.server.AlertManager.DeleteRule(id)
	if ok {
		e.configStore.SaveAlertRules(e.server.AlertManager.GetRules())
	}
	return ok
}

func (e *Engine) GetAlertHistory() []models.AlertEvent {
	return e.server.AlertManager.GetHistory()
}

func (e *Engine) ClearAlertHistory() {
	e.server.AlertManager.ClearHistory()
}
