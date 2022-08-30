# The Official ShieldRNN Implementation
This repository provides the official PyTorch implementation of the following paper:
> [ShieldRNN: A Distributed Flow-based DDoS Detection Solution For IoT Using Sequence Majority Voting](https://ieeexplore.ieee.org/document/9863841)

## How to use?
The main script is `train_shieldrnn.py` which is used to train the *ShieldRNN* model. To extract features from a single PCAP file, use `parse_data.py`. If you have a large PCAP file, you may use `run_multi_proc.sh` that will automatically split the large PCAP file into multiple smaller PCAP files, extract features in parallel, and combine them in the right order.

You can use the provided recipes to train the *ShieldRNN* model on CIC-IDS2017 data: 
- `run_train_wed.sh` to run the experiment of CIC-IDS2017-Wednesday.
- `run_train_fri.sh` to run the experiment of CIC-IDS2017-Friday.

you may also follow the same steps in the recipes to train *ShieldRNN* on your own data.

## Authors

-   **Faris Alasmary** - [farisalasmary](https://github.com/farisalasmary)

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/farisalasmary/shieldrnn/blob/main/LICENSE) file for details
## Citation

```
@article{alasmary2022shieldrnn,
	author={Alasmary, Faris and Alraddadi, Sulaiman and Al-Ahmadi, Saad and Al-Muhtadi, Jalal},
	journal={IEEE Access},
	title={ShieldRNN: A Distributed Flow-Based DDoS Detection Solution for IoT Using Sequence Majority Voting},
	year={2022},
	volume={10},
	number={},
	pages={88263-88275},
	doi={10.1109/ACCESS.2022.3200477}
}
```
