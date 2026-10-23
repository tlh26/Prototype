"use strict";

(() => {
    const table = document.getElementById("evidence-table");

    if (!table) {
        return;
    }

    const rows = Array.from(table.querySelectorAll("tbody tr"));
    const timestampFrom = document.getElementById("timestamp_from");
    const timestampTo = document.getElementById("timestamp_to");
    const eventType = document.getElementById("event_type");
    const eventSource = document.getElementById("event_source");
    const visibleCount = document.getElementById("evidence-visible-count");
    const filterStatus = document.getElementById("evidence-filter-status");
    const noMatches = document.getElementById("evidence-no-matches");
    const tableContainer = table.closest(".table-responsive");
    const parseUtcInput = (value) => (
        value ? Date.parse(`${value}:00Z`) : null
    );

    const applyFilters = () => {
        const fromValue = parseUtcInput(timestampFrom.value);
        const toValue = parseUtcInput(timestampTo.value);
        const inclusiveToValue = toValue === null ? null : toValue + 60_000;
        const selectedType = eventType.value.toLowerCase();
        const selectedSource = eventSource.value.trim().toLowerCase();
        let matchingRows = 0;

        rows.forEach((row) => {
            const timestamp = Date.parse(row.dataset.timestamp);
            const rowType = (row.dataset.eventType || "").toLowerCase();
            const rowSource = (row.dataset.source || "").toLowerCase();
            const matchesFrom = fromValue === null
                || (Number.isFinite(timestamp) && timestamp >= fromValue);
            const matchesTo = inclusiveToValue === null
                || (Number.isFinite(timestamp) && timestamp < inclusiveToValue);
            const matchesType = !selectedType || rowType === selectedType;
            const matchesSource = !selectedSource
                || rowSource.includes(selectedSource);
            const matches = matchesFrom
                && matchesTo
                && matchesType
                && matchesSource;

            row.hidden = !matches;

            if (matches) {
                matchingRows += 1;
            }
        });

        visibleCount.textContent = String(matchingRows);
        filterStatus.textContent = `Showing ${matchingRows} of ${rows.length} loaded evidence items.`;
        noMatches.hidden = matchingRows > 0;
        tableContainer.hidden = matchingRows === 0;
    };

    [timestampFrom, timestampTo, eventType, eventSource].forEach((control) => {
        control.addEventListener("input", applyFilters);
        control.addEventListener("change", applyFilters);
    });

    applyFilters();
})();
