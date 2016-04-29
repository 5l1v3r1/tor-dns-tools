args <- commandArgs(trailingOnly = TRUE)
input_file <- args[1]

cairo_pdf("asn-bwfrac.pdf", height=3.3, width=10)
data <- read.csv(input_file, header=TRUE)
data$time <- as.POSIXct(paste(data$time), format="%Y-%m-%dT%H:%M:%SZ")

# Subset data, i.e., select every second day.
# data <- subset(data, as.numeric(format(time, "%d")) %% 2 == 0)

# Make date ticks align with grid.  Taken from:
# <https://stackoverflow.com/questions/9119323/placing-the-grid-along-date-tickmarks>
my.grid <-function() {
        grid(nx=NA, ny=NULL)
        abline(v=axis.POSIXct(1, x=pretty(x), format="%b %Y"),
               col = "lightgray",
               lty = "dotted",
               lwd = par("lwd"))
}

x <- data$time
y <- data$as15169 # Google.

plot(x, y,
     type="o",
     pch=1,
     cex=0.5,
     lty=1,
     ylim=c(0,0.41),
     xlab="Time",
     ylab="Frac. of exit bandwidth",
     xaxt="n",
     col="#0000AA",
)

lines(x, data$as3356)
lines(x, data$as9008)
lines(x, data$as13030)
lines(x, data$as36692)
lines(x, data$as37560)
lines(x, data$as43350)
lines(x, data$as60781)

# Local resolvers.
lines(x, data$as0,
      type="o",
      pch=2,
      lty=2,
      cex=0.5,
      col="#AA0000")

# OVH.
lines(x, data$as16276,
      type="o",
      pch=3,
      lty=3,
      cex=0.5,
      col="#00AA00")

my.grid()

legend("topleft",
       c("Google", "Local", "OVH", "Other"),
       lty=c(1, 2, 3, 1),
       pch=c(1, 2, 3, NA),
       col=c("#0000AA", "#AA0000", "#00AA00", "#000000"),
       horiz=TRUE,
)

dev.off()
