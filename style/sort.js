(function() {
    console.log("Sort script file loaded.");

    document.addEventListener('DOMContentLoaded', () => {
        console.log("DOMContentLoaded event fired. Starting sort logic.");

        const table = document.getElementById('fileTable');
        console.log("Table element found:", table);
        if (!table) {
            console.log("Error: Table with ID 'fileTable' not found AFTER DOMContentLoaded.");
            return;
        }

        const headers = table.querySelectorAll('thead th[data-sort-by]');
        console.log("Headers found:", headers);

        const tbody = table.querySelector('tbody');
        console.log("Tbody found:", tbody);
        if (!tbody) {
            console.log("Error: Tbody element not found within the table.");
            return;
        }

        console.log("Attaching event listeners to headers...");
        headers.forEach(header => {
            console.log("Attaching listener to:", header);
            header.addEventListener('click', () => {
                console.log("Header clicked:", header);

                const sortColumn = header.dataset.sortBy;
                console.log("Sorting by column:", sortColumn);

                let sortDirection = header.dataset.sortDirection === 'asc' ? 'desc' : 'asc';
                console.log("New sort direction:", sortDirection);

                header.dataset.sortDirection = sortDirection;
                console.log("data-sort-direction set on clicked header:", header.dataset.sortDirection);

                headers.forEach(h => {
                     if (h !== header) {
                         h.dataset.sortDirection = '';
                     }
                });
                console.log("Other headers' direction attributes reset.");

                const rows = Array.from(tbody.querySelectorAll('tr'));
                console.log("Number of rows found:", rows.length);

                console.log("Starting row sorting...");
                rows.sort((rowA, rowB) => {
                    // --- Handle parent directory row ---
                    const isParentA = rowA.classList.contains('parent-dir');
                    const isParentB = rowB.classList.contains('parent-dir');

                    if (isParentA && !isParentB) return -1;
                    if (!isParentA && isParentB) return 1;
                    if (isParentA && isParentB) return 0;

                    // --- Regular row sorting ---
                    const valueA = rowA.dataset[sortColumn];
                    const valueB = rowB.dataset[sortColumn];
                    let comparison = 0;

                    if (sortColumn === 'name') {
                        const nameA = valueA.toLowerCase();
                        const nameB = valueB.toLowerCase();
                        if (nameA < nameB) comparison = -1;
                        else if (nameA > nameB) comparison = 1;
                        else comparison = 0;
                    } else if (sortColumn === 'size' || sortColumn === 'date') {
                        const numA = parseFloat(valueA);
                        const numB = parseFloat(valueB);
                        if (numA < numB) comparison = -1;
                        else if (numA > numB) comparison = 1;
                        else comparison = 0;
                    }
                    return sortDirection === 'asc' ? comparison : (comparison * -1);
                });
                console.log("Row sorting complete.");

                console.log("Clearing tbody content...");
                while (tbody.firstChild) {
                    tbody.removeChild(tbody.firstChild);
                }
                console.log("Tbody content cleared.");

                console.log("Appending sorted rows back to tbody...");
                rows.forEach(row => tbody.appendChild(row));
                console.log("Sorted rows appended.");
            });
        });
        console.log("Event listeners attached to headers.");

        console.log("Attempting initial sort trigger...");
        const nameHeader = table.querySelector('thead th[data-sort-by="name"]');
        if (nameHeader) {
            console.log("File Name header found for initial sort.");
            nameHeader.click();
            console.log("Initial click event triggered on File Name header.");
        } else {
            console.log("Error: File Name header not found for initial sort.");
        }

        console.log("Sort logic initialization complete.");
    });

    console.log("Sort script finished execution context setup (waiting for DOMContentLoaded).");

})();
