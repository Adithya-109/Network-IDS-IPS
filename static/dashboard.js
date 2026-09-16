function updateDashboard() {

    fetch("/api/statistics")
        .then(response => response.json())
        .then(data => {

            document.getElementById("total")
                .innerText = data.total;

            document.getElementById("port_scans")
                .innerText = data.port_scans;

            document.getElementById("syn_floods")
                .innerText = data.syn_floods;

            document.getElementById("high")
                .innerText = data.high;

        });


    fetch("/api/events")
        .then(response => response.json())
        .then(events => {

            const table =
                document.getElementById("events");

            table.innerHTML = "";

            events.forEach(event => {

                const row =
                    document.createElement("tr");

                row.innerHTML = `

                    <td>${event.timestamp}</td>

                    <td>${event.source_ip}</td>

                    <td>${event.destination_ip}</td>

                    <td>${event.attack_type}</td>

                    <td>
                        <span class="severity
                        ${event.severity.toLowerCase()}">
                            ${event.severity}
                        </span>
                    </td>

                    <td>${event.description}</td>

                `;

                table.appendChild(row);

            });

        });

}


// Update every 2 seconds

setInterval(updateDashboard, 2000);

updateDashboard();