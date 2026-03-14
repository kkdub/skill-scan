# Dynamic dispatch via vars() subscript
import builtins

fn = vars(builtins)["eval"]
fn("1+1")
