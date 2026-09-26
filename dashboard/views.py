from django.http import HttpResponse


def index(request):
    return HttpResponse(
        """
        <html>
            <head>
                <title>Evidence Correlation Dashboard</title>
            </head>
            <body>
                <h1>Evidence Correlation Dashboard</h1>
                <p>Dashboard foundation is operational.</p>
            </body>
        </html>
        """
    )