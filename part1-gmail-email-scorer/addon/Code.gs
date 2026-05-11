/**
 * Homepage card — shown when the add-on is opened without a message context.
 */
function buildHomepageCard() {
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Scorer'))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          'Open an email to scan it for maliciousness signals.'
        )
      )
    )
    .build();
  return [card];
}

/**
 * Contextual trigger — fires when the user opens a Gmail message.
 * For now: stub card. Backend integration comes next.
 */
function buildScanCard(e) {
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Scorer'))
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText('Scan card placeholder.'))
        .addWidget(
          CardService.newTextButton()
            .setText('Analyze this email')
            .setOnClickAction(CardService.newAction().setFunctionName('onScanClicked'))
        )
    )
    .build();
  return [card];
}

function onScanClicked() {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText('Scan clicked — backend wiring coming next.')
    )
    .build();
}
