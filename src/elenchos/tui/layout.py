from __future__ import annotations

from dataclasses import dataclass

PROMPT_PANEL = "prompt"
RATIONALE_PANEL = "rationale"
POLICY_PANEL = "policy"
SELF_CORRECTION_PANEL = "self_correction"
RUN_STATUS_PANEL = "run_status"
FINAL_PANEL = "final"

PANEL_ORDER = (
    PROMPT_PANEL,
    RATIONALE_PANEL,
    POLICY_PANEL,
    SELF_CORRECTION_PANEL,
    RUN_STATUS_PANEL,
    FINAL_PANEL,
)
WIDE_MIN_COLUMNS = 120
HEADER_HEIGHT = 2
FOOTER_HEIGHT = 1
MIN_PANEL_HEIGHT = 3
MIN_PROMPT_HEIGHT = 4
MIN_FINAL_HEIGHT = 5
PANEL_GAP = 0


@dataclass(frozen=True, slots=True)
class Rect:
    y: int
    x: int
    height: int
    width: int


@dataclass(frozen=True, slots=True)
class PanelPlacement:
    panel_id: str
    rect: Rect


@dataclass(frozen=True, slots=True)
class ScreenLayout:
    width: int
    height: int
    is_wide: bool
    header: Rect
    footer: Rect
    panels: tuple[PanelPlacement, ...]

    def panel_ids(self) -> tuple[str, ...]:
        return tuple(panel.panel_id for panel in self.panels)


def choose_layout(width: int, height: int) -> ScreenLayout:
    safe_width = max(width, 40)
    safe_height = max(height, 10)
    header = Rect(0, 0, min(HEADER_HEIGHT, safe_height), safe_width)
    footer = Rect(max(0, safe_height - FOOTER_HEIGHT), 0, FOOTER_HEIGHT, safe_width)
    body_y = header.height
    body_height = max(MIN_PANEL_HEIGHT, safe_height - header.height - footer.height)
    is_wide = safe_width >= WIDE_MIN_COLUMNS
    panels = (
        _wide_panels(safe_width, body_y, body_height)
        if is_wide
        else _stacked_panels(safe_width, body_y, body_height)
    )
    return ScreenLayout(
        width=safe_width,
        height=safe_height,
        is_wide=is_wide,
        header=header,
        footer=footer,
        panels=panels,
    )


def _wide_panels(width: int, body_y: int, body_height: int) -> tuple[PanelPlacement, ...]:
    prompt_height = min(max(MIN_PROMPT_HEIGHT, body_height // 5), 5)
    final_height = min(max(MIN_FINAL_HEIGHT, body_height // 3), max(MIN_PANEL_HEIGHT, body_height))
    middle_height = max(MIN_PANEL_HEIGHT, body_height - prompt_height - final_height)
    left_width = width // 2
    right_width = width - left_width
    top_y = body_y
    middle_y = top_y + prompt_height
    final_y = middle_y + middle_height
    upper_middle = max(MIN_PANEL_HEIGHT, middle_height // 2)
    lower_middle = max(MIN_PANEL_HEIGHT, middle_height - upper_middle)
    if upper_middle + lower_middle > middle_height:
        upper_middle = max(MIN_PANEL_HEIGHT, middle_height - MIN_PANEL_HEIGHT)
        lower_middle = max(MIN_PANEL_HEIGHT, middle_height - upper_middle)

    return (
        PanelPlacement(PROMPT_PANEL, Rect(top_y, 0, prompt_height, width)),
        PanelPlacement(RATIONALE_PANEL, Rect(middle_y, 0, upper_middle, left_width)),
        PanelPlacement(POLICY_PANEL, Rect(middle_y + upper_middle, 0, lower_middle, left_width)),
        PanelPlacement(
            SELF_CORRECTION_PANEL,
            Rect(middle_y, left_width, upper_middle, right_width),
        ),
        PanelPlacement(
            RUN_STATUS_PANEL,
            Rect(middle_y + upper_middle, left_width, lower_middle, right_width),
        ),
        PanelPlacement(FINAL_PANEL, Rect(final_y, 0, max(MIN_PANEL_HEIGHT, final_height), width)),
    )


def _stacked_panels(width: int, body_y: int, body_height: int) -> tuple[PanelPlacement, ...]:
    weights = {
        PROMPT_PANEL: 4,
        RATIONALE_PANEL: 4,
        POLICY_PANEL: 4,
        SELF_CORRECTION_PANEL: 3,
        RUN_STATUS_PANEL: 4,
        FINAL_PANEL: 6,
    }
    min_heights = {
        PROMPT_PANEL: MIN_PROMPT_HEIGHT,
        RATIONALE_PANEL: MIN_PANEL_HEIGHT,
        POLICY_PANEL: MIN_PANEL_HEIGHT,
        SELF_CORRECTION_PANEL: MIN_PANEL_HEIGHT,
        RUN_STATUS_PANEL: MIN_PANEL_HEIGHT,
        FINAL_PANEL: MIN_FINAL_HEIGHT,
    }
    minimum_total = sum(min_heights.values())
    heights: dict[str, int]
    if body_height >= minimum_total:
        extra = body_height - minimum_total
        total_weight = sum(weights.values())
        heights = {
            panel_id: min_heights[panel_id] + (extra * weights[panel_id]) // total_weight
            for panel_id in PANEL_ORDER
        }
        remainder = body_height - sum(heights.values())
        for panel_id in reversed(PANEL_ORDER):
            if remainder <= 0:
                break
            heights[panel_id] += 1
            remainder -= 1
    else:
        heights = _compressed_heights(body_height)

    y = body_y
    placements: list[PanelPlacement] = []
    for panel_id in PANEL_ORDER:
        panel_height = max(1, heights[panel_id])
        placements.append(PanelPlacement(panel_id, Rect(y, 0, panel_height, width)))
        y += panel_height + PANEL_GAP
    return tuple(placements)


def _compressed_heights(body_height: int) -> dict[str, int]:
    heights = {panel_id: MIN_PANEL_HEIGHT for panel_id in PANEL_ORDER}
    heights[PROMPT_PANEL] = MIN_PROMPT_HEIGHT
    heights[FINAL_PANEL] = MIN_FINAL_HEIGHT
    while sum(heights.values()) > body_height and max(heights.values()) > 1:
        for panel_id in (
            SELF_CORRECTION_PANEL,
            RATIONALE_PANEL,
            POLICY_PANEL,
            RUN_STATUS_PANEL,
            PROMPT_PANEL,
            FINAL_PANEL,
        ):
            if sum(heights.values()) <= body_height:
                break
            if heights[panel_id] > 1:
                heights[panel_id] -= 1
    return heights


def visible_panel_ids(width: int, height: int) -> tuple[str, ...]:
    return choose_layout(width, height).panel_ids()
