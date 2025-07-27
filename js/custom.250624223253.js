/* JS for preset "Season (snow)" */
//Snowing
if (!$("body").hasClass("edit")) {
  window.addEventListener('DOMContentLoaded', function() {
    //canvas init
    var canvas = document.getElementById("snow");
    var ctx = canvas.getContext("2d");

    //canvas dimensions
    var W = window.innerWidth;
    var H = window.innerHeight;
    canvas.width = W;
    canvas.height = H;

    //snowflake particles
    var mp = 250; //max particles
    var particles = [];
    for (var i = 0; i < mp; i++) {
      particles.push({
        x: Math.random() * W, //x-coordinate
        y: Math.random() * H, //y-coordinate
        r: Math.random() * 4 + 1, //radius
        d: Math.random() * mp //density
      });
    }

    //Lets draw the flakes
    function draw() {
      ctx.clearRect(0, 0, W, H);

      ctx.fillStyle = "rgba(255, 255, 255, 0.8)";
      ctx.beginPath();
      for (var i = 0; i < mp; i++) {
        var p = particles[i];
        ctx.moveTo(p.x, p.y);
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2, true);
      }
      ctx.fill();
      update();
    }

    //Function to move the snowflakes
    //angle will be an ongoing incremental flag. Sin and Cos functions will be applied to it to create vertical and horizontal movements of the flakes
    var angle = 0;
    function update() {
      angle += 0.01;
      for (var i = 0; i < mp; i++) {
        var p = particles[i];
        //Updating X and Y coordinates
        //We will add 1 to the cos function to prevent negative values which will lead flakes to move upwards
        //Every particle has its own density which can be used to make the downward movement different for each flake
        //Lets make it more random by adding in the radius
        p.y += Math.cos(angle + p.d) + 1 + p.r / 2;
        p.x += Math.sin(angle) * 2;

        //Sending flakes back from the top when it exits
        //Lets make it a bit more organic and let flakes enter from the left and right also.
        if (p.x > W + 5 || p.x < -5 || p.y > H) {
          if (i % 3 > 0) {
            //66.67% of the flakes
            particles[i] = { x: Math.random() * W, y: -10, r: p.r, d: p.d };
          } else {
            //If the flake is exitting from the right
            if (Math.sin(angle) > 0) {
              //Enter from the left
              particles[i] = { x: -5, y: Math.random() * H, r: p.r, d: p.d };
            } else {
              //Enter from the right
              particles[i] = { x: W + 5, y: Math.random() * H, r: p.r, d: p.d };
            }
          }
        }
      }
    }

    //animation loop
    setInterval(draw, 33);
  });
}

/* End JS for preset "Season (snow)" */
/* JS for preset "Horizontal form V3" */
(function() {
	$(function() {
		if (!$('body').is('.edit')) {
			$('.horizontal-form').each(function() {
				$(this).click(function() {
					$('.ed-form-captcha', this).addClass('show');
					$('.ed-form-checkbox.privacy', this).addClass('show');
				});
			});
		}
	});
})();

/* End JS for preset "Horizontal form V3" */

/* JS for preset "Countdown V3" */
$(function() {
	var isIE11 = !!window.MSInputMethodContext && !!document.documentMode,
		isSafari =
		navigator.userAgent.toLowerCase().indexOf('safari') > -1 &&
		navigator.userAgent.toLowerCase().indexOf('chrome') === -1;

	var slice = Array.prototype.slice;

	var valid = true;

	var ready = function(callback) {
		var fn = function() {
			if (document.body.classList.contains('edit')) {
				return;
			}
			callback();
		};

		if (window.readyState !== 'loading') {
			fn();
			return;
		}

		document.addEventListener('DOMContentLoaded', fn);
	}

	var countdown = function(date, tick) {
		var now = new Date().getTime(),
			running = false,
			days = 0,
			hours = 0,
			minutes = 0,
			seconds,
			interval;

		var updateCounter = function() {
			if (!running) return;

			now = new Date().getTime();
			seconds = Math.round((date - now) / 1000);

			if (seconds > 86400) {
				days = Math.floor(seconds / 86400);
				seconds %= 86400;
			}

			if (seconds > 3600) {
				hours = Math.floor(seconds / 3600);
				seconds %= 3600;
			}

			if (seconds > 60) {
				minutes = Math.floor(seconds / 60);
				seconds %= 60;
			}

			tick(days, hours, minutes, seconds);
		};

        if (isNaN(Date.parse(date))) {
		    date = date.replace(/\-/g, '/');
		}
		if (isNaN(Date.parse(date))) {
		    date = date.replace(/\s/, 'T');
		}

		date = new Date(date).getTime();


		if (now >= date) {
			valid = false;
			return;
		}

		tick = tick || (function() {});

		return {
			start: function() {
				interval = window.setInterval(updateCounter, 1000);
				running = true;
				updateCounter();
			},
			stop: function() {
				if (interval) window.clearInterval(interval);
				interval = undefined;
				running = false;
			}
		}
	};

	var writeCountdown = function(element, days, hours, minutes, seconds) {
		var daysElm = element.querySelector(".countdown-days"),
			hoursElm = element.querySelector('.countdown-hours'),
			minutesElm = element.querySelector('.countdown-minutes'),
			secondsElm = element.querySelector('.countdown-seconds');

		if (daysElm) daysElm.innerHTML = days;
		if (hoursElm) hoursElm.innerHTML = hours;
		if (minutesElm) minutesElm.innerHTML = minutes;
		if (secondsElm) secondsElm.innerHTML = seconds;
	}

	var buildCountdown = function(e) {
		var instances = slice.call(document.querySelectorAll('.countdown-instance')),
			len = instances.length,
			i = 0,
			element, 
			dataContent;

		for (; i < len; i++) {
			element = instances[i];
			dataContent = window.getComputedStyle(instances[i], ':before').content.slice(1, -1);
			
			var date = dataContent;

			element.countdown = countdown(date, function(days, hours, minutes, seconds) {
				writeCountdown(
					element, parseInt(days),
					("0" + parseInt(hours)).slice(-2),
					("0" + parseInt(minutes)).slice(-2),
					("0" + parseInt(seconds)).slice(-2)
				);
			});

			if (valid) {
				element.countdown.start();
			}
		}
	};

	var destroyCountdown = function(e) {
		var instances = slice.call(document.querySelectorAll('.countdown-instance')),
			len = instances.length,
			i = 0,
			element;
		for (; i < len; i++) {
			element = instances[i];
			writeCountdown(element, "0", "0", "0", "0");
			element.countdown.stop();
		}
	}

	var preview = false;
	var listener = function() {
		if (valid) {
			if (!preview && document.body.classList.contains('preview')) {
				buildCountdown();
				preview = true;
			} else if (preview && !document.body.classList.contains('preview')) {
				destroyCountdown();
				preview = false;
			}
		}
    
		requestAnimationFrame(listener);
	};

	requestAnimationFrame(listener);
	ready(function() {
		buildCountdown();
	});
});

/* End JS for preset "Countdown V3" */