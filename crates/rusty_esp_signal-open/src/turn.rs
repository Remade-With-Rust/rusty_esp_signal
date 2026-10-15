//! Whose frame a splice sends first when the stack's own and a relayed one
//! both wait: a shedding policy's "relayed traffic behind the device's own"
//! is kept
//! where the two meet, at the one radio queue they share. While relaying is
//! put behind, the device's own frame always goes first and relayed frames
//! back up in their bounded crossing (where a full one drops: the plan's
//! backpressure); otherwise the two take turns. The access category the
//! radio sends either in is unchanged (best effort). Not Wi-Fi certified.

/// Which waiting frame goes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum First {
    /// The stack's own frame (the device's traffic).
    Stack,
    /// A relayed frame, from the other side's splice.
    Across,
}

/// The turn-taking between the stack's frames and relayed ones.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Turns {
    across_went_last: bool,
}

impl Turns {
    /// Nobody has gone yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            across_went_last: false,
        }
    }

    /// Who goes first now: with `relay_behind`, always the stack's own;
    /// otherwise whichever did not go last.
    #[must_use]
    pub const fn first(&self, relay_behind: bool) -> First {
        if relay_behind || self.across_went_last {
            First::Stack
        } else {
            First::Across
        }
    }

    /// Who went.
    pub fn served(&mut self, who: First) {
        self.across_went_last = who == First::Across;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn they_take_turns_unless_relaying_is_put_behind() {
        let mut t = Turns::new();
        // taking turns
        let mut order = [First::Stack; 4];
        for slot in &mut order {
            let who = t.first(false);
            *slot = who;
            t.served(who);
        }
        assert_eq!(
            order,
            [First::Across, First::Stack, First::Across, First::Stack]
        );
        // put behind: the stack's own every time, whoever went last
        t.served(First::Stack);
        assert_eq!(t.first(true), First::Stack);
        t.served(First::Across);
        assert_eq!(t.first(true), First::Stack);
        // and back to turns when the ladder lets go
        t.served(First::Stack);
        assert_eq!(t.first(false), First::Across);
    }
}
