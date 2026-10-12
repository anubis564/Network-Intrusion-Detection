"""Theme, CSS and small HTML components shared by the pages."""
import html

import numpy as np
import streamlit as st

from core.config import COLORS, SEVERITY_COLORS

CSS = f"""
<style>
:root {{ --card:{COLORS['card']}; --border:{COLORS['border']}; --muted:{COLORS['muted']}; }}
.block-container {{ padding-top: 2.2rem; padding-bottom: 2rem; max-width: 1500px; }}
[data-testid="stSidebar"] {{ background: #0a0f1d; border-right: 1px solid var(--border); }}
div[data-testid="stVerticalBlockBorderWrapper"] {{ background: var(--card); border-color: var(--border) !important;
    border-radius: 14px; }}
h1, h2, h3 {{ letter-spacing: -0.01em; }}
.page-title {{ font-size: 1.65rem; font-weight: 700; margin: 0; }}
.page-sub {{ color: var(--muted); font-size: .92rem; margin-top: .15rem; }}
.kpi {{ background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 14px 16px 10px;
    height: 100%; }}
.kpi .label {{ color: var(--muted); font-size: .82rem; }}
.kpi .value {{ font-size: 1.75rem; font-weight: 700; margin: 2px 0 2px; }}
.kpi .foot {{ display: flex; justify-content: space-between; align-items: flex-end; gap: 8px; }}
.kpi .delta {{ font-size: .78rem; font-weight: 600; text-align: right; }}
.kpi .delta small {{ display: block; color: var(--muted); font-weight: 400; }}
.badge {{ display: inline-block; padding: 2px 10px; border-radius: 6px; font-size: .75rem; font-weight: 600;
    border: 1px solid; }}
.chip {{ display: inline-block; padding: 2px 9px; margin: 2px 4px 2px 0; border-radius: 999px; font-size: .75rem;
    background: #1b2540; color: #c7d2fe; border: 1px solid #2b3a63; }}
table.alerts {{ width: 100%; border-collapse: collapse; font-size: .84rem; }}
table.alerts th {{ text-align: left; color: var(--muted); font-weight: 500; padding: 8px 6px;
    border-bottom: 1px solid var(--border); }}
table.alerts td {{ padding: 9px 6px; border-bottom: 1px solid #172036; }}
.act-blocked {{ color: #f87171; font-weight: 600; }} .act-logged {{ color: #60a5fa; font-weight: 600; }}
.statusbar {{ margin: 8px 0 14px; }}
.statusbar .row {{ display: flex; justify-content: space-between; font-size: .85rem; margin-bottom: 5px; }}
.statusbar .track {{ height: 7px; background: #1c2640; border-radius: 99px; overflow: hidden; }}
.statusbar .fill {{ height: 100%; border-radius: 99px; }}
.verdict {{ border-radius: 14px; padding: 18px 20px; border: 1px solid; }}
.verdict .big {{ font-size: 1.6rem; font-weight: 800; }}
.feed-item {{ border-left: 3px solid; padding: 6px 10px; margin-bottom: 6px; background: #0e1628; border-radius: 6px;
    font-size: .83rem; }}
.brand {{ display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 1.25rem; margin-bottom: .2rem; }}
.brand .shield {{ width: 34px; height: 34px; border-radius: 10px; display: grid; place-items: center;
    background: linear-gradient(135deg, #6366f1, #3b82f6); }}
.dot {{ height: 9px; width: 9px; border-radius: 50%; display: inline-block; margin-right: 6px; }}
/* chat replies: each paragraph takes its direction from its own text, so Arabic answers read right-to-left */
[data-testid="stChatMessage"] :is(p, li, h1, h2, h3, h4, blockquote) {{ unicode-bidi: plaintext; text-align: start; }}
[data-testid="stChatMessage"] :is(ul, ol):has(> li:first-child > :is(p, span)) {{ unicode-bidi: plaintext; }}
</style>
"""


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)


def page_header(title: str, subtitle: str = ""):
    st.markdown(f'<p class="page-title">{html.escape(title)}</p>'
                + (f'<p class="page-sub">{html.escape(subtitle)}</p>' if subtitle else ""), unsafe_allow_html=True)


def sparkline(values, color: str, width: int = 120, height: int = 34) -> str:
    v = np.asarray(values, dtype=float)
    if len(v) < 2 or np.allclose(v.max(), v.min()):
        v = np.array([0.5, 0.5])
        lo, hi = 0, 1
    else:
        lo, hi = v.min(), v.max()
    xs = np.linspace(2, width - 2, len(v))
    ys = height - 3 - (v - lo) / (hi - lo) * (height - 6)
    pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    return (f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
            f'<polyline fill="none" stroke="{color}" stroke-width="1.8" points="{pts}"/></svg>')


def kpi_card(label: str, value: str, color: str, spark=None, delta: str = "", delta_note: str = "",
             delta_color: str | None = None) -> str:
    delta_html = (f'<div class="delta" style="color:{delta_color or color}">{html.escape(delta)}'
                  f'<small>{html.escape(delta_note)}</small></div>') if delta else ""
    spark_html = sparkline(spark, color) if spark is not None else ""
    return (f'<div class="kpi"><div class="label">{html.escape(label)}</div><div class="value">{html.escape(value)}</div>'
            f'<div class="foot">{spark_html}{delta_html}</div></div>')


def kpi_row(cards: list[str]):
    cols = st.columns(len(cards))
    for col, card in zip(cols, cards):
        col.markdown(card, unsafe_allow_html=True)


def severity_badge(sev: str) -> str:
    c = SEVERITY_COLORS.get(sev, COLORS["muted"])
    return f'<span class="badge" style="color:{c};border-color:{c}55;background:{c}1a">{html.escape(sev)}</span>'


def chips(items) -> str:
    return "".join(f'<span class="chip">{html.escape(i)}</span>' for i in items)


def status_bar(label: str, value_text: str, fraction: float, color: str) -> str:
    pct = max(0.0, min(1.0, fraction)) * 100
    return (f'<div class="statusbar"><div class="row"><span>{html.escape(label)}</span><span>{html.escape(value_text)}</span></div>'
            f'<div class="track"><div class="fill" style="width:{pct:.0f}%;background:{color}"></div></div></div>')


def plotly_layout(fig, height: int = 320, legend: bool = True):
    fig.update_layout(
        template="plotly_dark", height=height, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=8, r=8, t=30, b=8), font=dict(color=COLORS["text"], size=12),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0) if legend else None,
        showlegend=legend,
    )
    fig.update_xaxes(gridcolor="#1c2640", zeroline=False)
    fig.update_yaxes(gridcolor="#1c2640", zeroline=False)
    return fig


def fmt_int(n) -> str:
    return f"{int(n):,}"
