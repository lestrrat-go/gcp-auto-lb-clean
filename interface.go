package autolbclean

import compute "google.golang.org/api/compute/v1"

const globalRegion = "global"

type App struct {
	project string
	service *compute.Service
}
