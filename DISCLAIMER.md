# Legal Disclaimer

`modpao` ("the Software") is a Modbus / Operational-Technology security testing
tool intended for **authorized security research, education, and penetration
testing only**.

## Authorized use only

You may use the Software **only** on Modbus/ICS/SCADA systems that:

1. you own, or
2. you have received **explicit, written authorization** to test from the
   system owner.

Using the Software to access, scan, read from, write to, disrupt, or otherwise
interact with any device or network **without authorization is prohibited** and
may violate computer-crime, wiretapping, critical-infrastructure, and other laws
in your jurisdiction (for example, but not limited to, the U.S. Computer Fraud
and Abuse Act and equivalent legislation elsewhere).

## Safety warning

Modbus has no built-in authentication or integrity protection. Operations
performed by this Software — including writes to coils and registers, function
codes such as FC05/06/15/16/23, flooding, and authentication replay — can:

- start, stop, or alter physical processes and equipment,
- change setpoints or disable safety interlocks,
- cause equipment damage, environmental harm, or **injury or loss of life**,
- disrupt or deny service on operational networks.

**Never** run write, persist, flood, or authentication operations against a
production or safety-critical system unless you fully understand the
consequences and are explicitly authorized to do so.

## No warranty / no liability

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES, DOWNTIME, PHYSICAL HARM, DATA LOSS, OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

**You are solely responsible for your actions and for complying with all
applicable laws and regulations.** By using the Software you accept full
responsibility for any consequences of its use.
