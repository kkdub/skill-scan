# Dynamic dispatch via __dict__ attribute subscript
import os

fn = os.__dict__["system"]
fn("ls")
