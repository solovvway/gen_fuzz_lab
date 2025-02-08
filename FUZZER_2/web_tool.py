from flask import Flask, request, jsonify, render_template
from cli_tool.structures import *
from feedback.feedback import *
from traffic_view.view_2 import *

app = Flask(__name__)

sniffer = None
uniq_dump = []
uniq_protocols = set()
proto_weights = {}
weights = {
    'crossovers': [99, 3],
    'mutations': [99, 2, 1, 1, 2, 1, 1, 1]
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_sniffing', methods=['POST'])
def start_sniffing():
    global sniffer, uniq_dump, uniq_protocols
    network = request.json['network']
    sniffer = Sniffer(iface='lo', network=network)
    print("\nАсинхронный перехват:")
    sniffer.async_sniff()
    return jsonify({"status": "Sniffing started"})

@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing():
    global sniffer, uniq_dump, uniq_protocols
    dump = sniffer.stop_async_sniff()
    uniq_dump = []
    uniq_protocols = set()
    for pkt in dump:
        ip_src = getattr(pkt.__getitem__('IP'), 'src', None)
        ip_dst = getattr(pkt.__getitem__('IP'), 'dst', None)
        mac_src = getattr(pkt.__getitem__('Ether'), 'src', None)
        mac_dst = getattr(pkt.__getitem__('Ether'), 'dst', None)
        layers = pkt.layers()
        unit_instance = Unit(ip_src=ip_src, ip_dst=ip_dst, mac_src=mac_src, mac_dst=mac_dst, layers=layers, pdu=pkt)
        if unit_instance not in uniq_dump:
            uniq_dump.append(unit_instance)
        for layer in layers:
            uniq_protocols.add(layer.__name__)
    return jsonify({"status": "Sniffing stopped", "uniq_protocols": list(uniq_protocols)})

@app.route('/set_proto_weights', methods=['POST'])
def set_proto_weights():
    global proto_weights
    proto_weights = request.json['proto_weights']
    return jsonify({"status": "Protocol weights set", "proto_weights": proto_weights})

@app.route('/set_weights', methods=['POST'])
def set_weights():
    global weights
    weights = request.json['weights']
    return jsonify({"status": "Weights set", "weights": weights})

@app.route('/generate_traffic', methods=['POST'])
def generate_traffic():
    global uniq_dump, proto_weights, weights
    # Check if all protocols have weights
    missing_protocols = [proto for proto in uniq_protocols if proto not in proto_weights]
    if missing_protocols:
        return jsonify({"status": "Error", "message": f"Weights missing for protocols: {missing_protocols}"}), 400

    population = Population()
    for i in uniq_dump:
        weight = proto_weights[i.pdu.lastlayer()._name]
        population.add(i, weight)
    mutator = Mutator(weights)
    a, b = population.choice_two()
    pkt_after_fuzz = mutator.gen_fuzz(a, b)
    sender = Sender(iface="lo")
    sender.send_packet(pkt_after_fuzz)
    return jsonify({"status": "Traffic generated", "packet": pkt_after_fuzz.command()})

if __name__ == '__main__':
    app.run(debug=True)