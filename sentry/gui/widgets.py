"""
Sentry Antivirus - Custom Widgets
"""
import tkinter as tk
import customtkinter as ctk


class AnimatedSwitch(ctk.CTkFrame):
    """Smooth animated toggle switch with color interpolation."""

    TRACK_W = 52
    TRACK_H = 28
    KNOB_D = 22
    PAD = 3
    ON_COLOR = "#03fc88"
    OFF_COLOR = "#6b6b6b"
    STEPS = 15
    STEP_MS = 10  # ~150 ms total

    def __init__(self, parent, command=None, onvalue=True, offvalue=False, **kwargs):
        super().__init__(parent, fg_color="transparent",
                         width=self.TRACK_W, height=self.TRACK_H, **kwargs)
        self._command = command
        self._onvalue = onvalue
        self._offvalue = offvalue
        self._state = False
        self._animating = False
        self._knob_x = float(self.PAD + self.KNOB_D / 2)

        mode = ctk.get_appearance_mode()
        bg = "#2b2b2b" if mode == "Dark" else "#dbdbdb"

        self._canvas = tk.Canvas(
            self,
            width=self.TRACK_W,
            height=self.TRACK_H,
            bg=bg,
            highlightthickness=0,
            cursor="hand2",
        )
        self._canvas.pack()
        self._redraw()
        self._canvas.bind("<Button-1>", self._on_click)

    @staticmethod
    def _lerp_color(c1: str, c2: str, t: float) -> str:
        r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
        r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
        return "#{:02x}{:02x}{:02x}".format(
            int(r1 + (r2 - r1) * t),
            int(g1 + (g2 - g1) * t),
            int(b1 + (b2 - b1) * t),
        )

    @staticmethod
    def _ease(t: float) -> float:
        """Smooth ease-in-out (cubic Hermite)."""
        return t * t * (3 - 2 * t)

    def _redraw(self, knob_x: float = None):
        if knob_x is None:
            knob_x = self._knob_x
        w, h = self.TRACK_W, self.TRACK_H
        r = h // 2
        knob_off = self.PAD + self.KNOB_D / 2
        knob_on = w - self.PAD - self.KNOB_D / 2
        progress = (knob_x - knob_off) / (knob_on - knob_off)
        progress = max(0.0, min(1.0, progress))
        track = self._lerp_color(self.OFF_COLOR, self.ON_COLOR, progress)

        self._canvas.delete("all")

        # Track (rounded rectangle via two arcs + rectangle)
        self._canvas.create_arc(0, 0, h, h, start=90, extent=180, fill=track, outline="")
        self._canvas.create_arc(w - h, 0, w, h, start=270, extent=180, fill=track, outline="")
        self._canvas.create_rectangle(r, 0, w - r, h, fill=track, outline="")

        # Knob shadow
        kr = self.KNOB_D // 2
        ky = h // 2
        self._canvas.create_oval(
            knob_x - kr + 1, ky - kr + 1,
            knob_x + kr + 1, ky + kr + 1,
            fill="#3a3a3a", outline="",
        )
        # Knob
        self._canvas.create_oval(
            knob_x - kr, ky - kr,
            knob_x + kr, ky + kr,
            fill="#ffffff", outline="",
        )

    def _on_click(self, _event=None):
        if self._animating:
            return
        self._state = not self._state
        self._animate()
        if self._command:
            self._command()

    def _animate(self):
        self._animating = True
        start = self._knob_x
        end = float(self.TRACK_W - self.PAD - self.KNOB_D / 2) if self._state \
              else float(self.PAD + self.KNOB_D / 2)

        def step(i):
            if i > self.STEPS:
                self._knob_x = end
                self._animating = False
                return
            t = self._ease(i / self.STEPS)
            x = start + (end - start) * t
            self._knob_x = x
            self._redraw(x)
            self._canvas.after(self.STEP_MS, lambda: step(i + 1))

        step(1)

    def get(self):
        return self._onvalue if self._state else self._offvalue

    def select(self):
        """Programmatically set to ON (no animation)."""
        if not self._state:
            self._state = True
            self._knob_x = float(self.TRACK_W - self.PAD - self.KNOB_D / 2)
            self._redraw()

    def deselect(self):
        """Programmatically set to OFF (no animation)."""
        if self._state:
            self._state = False
            self._knob_x = float(self.PAD + self.KNOB_D / 2)
            self._redraw()
