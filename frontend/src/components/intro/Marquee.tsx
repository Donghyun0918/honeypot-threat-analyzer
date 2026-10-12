// 흐르는 띠. 문구를 두 번 넣고 트랙을 정확히 절반만큼 밀어 이음매를 없앤다.

type MarqueeProps = {
  text: string;
  direction?: "left" | "right";
  variant?: "accent" | "subtle";
};

export default function Marquee({ text, direction = "left", variant = "accent" }: MarqueeProps) {
  return (
    <section className={`ix-marquee ${variant}`} aria-hidden="true">
      <div className={`ix-marquee-track ${direction === "left" ? "l" : "r"}`}>
        <span>{text}&nbsp;</span>
        <span>{text}&nbsp;</span>
      </div>
    </section>
  );
}
