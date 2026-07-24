package policy

type Action string

const (
	ActionBlock   Action = "block"
	ActionMask    Action = "mask"
	ActionLogOnly Action = "log_only"
)

var validActions = map[Action]bool{
	ActionBlock:   true,
	ActionMask:    true,
	ActionLogOnly: true,
}
